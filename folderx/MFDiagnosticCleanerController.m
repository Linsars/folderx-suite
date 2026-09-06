#import "MFDiagnosticCleanerController.h"
#import <UIKit/UIKit.h>
#import <dlfcn.h>

// libroot 函数指针（动态加载）
static const char *(*g_libroot_jbrootpath)(void) = NULL;
static const char *(*g_libroot_rootfspath)(void) = NULL;

static void mfLoadLibroot(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *handle = dlopen("/var/jb/usr/lib/libroot.dylib", RTLD_LAZY);
        if (!handle) handle = dlopen("/usr/lib/libroot.dylib", RTLD_LAZY);
        if (!handle) handle = dlopen("@rpath/libroot.dylib", RTLD_LAZY);
        if (handle) {
            g_libroot_jbrootpath = (const char *(*)(void))dlsym(handle, "libroot_jbrootpath");
            g_libroot_rootfspath = (const char *(*)(void))dlsym(handle, "libroot_rootfspath");
        }
    });
}

static const char *g_diagPaths[] = {
    "/var/mobile/Library/Logs",
    "/var/mobile/Library/Analytics",
    "/var/db/analyticsd",
    "/var/mobile/Library/Caches/com.apple.analytics",
    "/var/mobile/Library/Caches/com.apple.DiagnosticData",
    "/var/mobile/Library/Caches/com.apple.CrashReporter",
    "/var/mobile/Library/Caches/com.apple.analyticsd",
    "/var/mobile/Library/Caches/com.apple.MobileGestaltHelper",
    "/var/mobile/Library/Caches/com.apple.MessagesAnalytics",
    "/var/mobile/Library/Caches/com.apple.SafariAnalytics",
    "/var/mobile/Library/Application Support/com.apple.analytics",
    "/var/mobile/Library/Application Support/DiagnosticLogs",
    "/var/root/Library/Logs",
    "/var/root/Library/Analytics",
    "/private/var/log",
    NULL
};

// 受保护路径：即使能遍历也无法删除，跳过以避免误报失败
static const char *g_skipPaths[] = {
    "/var/db/analyticsd",
    "/var/mobile/Library/Logs/com.apple.ioam",
    "/var/root/Library/Logs/MobileContainerManager",
    "/private/var/log/com.apple.xpc.launchd",
    NULL
};

static BOOL mfShouldSkipPath(NSString *path) {
    for (int i = 0; g_skipPaths[i]; i++) {
        if ([path hasPrefix:[NSString stringWithUTF8String:g_skipPaths[i]]]) {
            return YES;
        }
    }
    return NO;
}

@interface MFDiagnosticCleanerController ()
@property (nonatomic, strong) UIAlertController *loadingAlert;
@property (nonatomic, strong) NSString *cleanupMessage;
@property (nonatomic, assign) BOOL cleanupSuccess;
@end

@implementation MFDiagnosticCleanerController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"诊断日志清理";
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self showCleanupAlert];
}

- (void)showCleanupAlert {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"清理诊断数据"
                                                                   message:@"确定要删除所有诊断、分析、崩溃日志和缓存吗？此操作不可撤销。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        [self.navigationController popViewControllerAnimated:YES];
    }];
    [alert addAction:cancelAction];
    
    UIAlertAction *cleanupAction = [UIAlertAction actionWithTitle:@"清理" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        [self startCleanup];
    }];
    [alert addAction:cleanupAction];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)startCleanup {
    self.loadingAlert = [UIAlertController alertControllerWithTitle:nil
                                                            message:@"正在清理…"
                                                     preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:self.loadingAlert animated:YES completion:nil];
    
    // 在后台线程执行清理
    [self performSelectorInBackground:@selector(doCleanupInBackground) withObject:nil];
}

- (void)doCleanupInBackground {
    mfLoadLibroot();
    const char *jbroot = g_libroot_jbrootpath ? g_libroot_jbrootpath() : "";
    const char *rootfs = g_libroot_rootfspath ? g_libroot_rootfspath() : "";
    
    NSMutableArray *targetPaths = [NSMutableArray array];
    
    for (int i = 0; g_diagPaths[i]; i++) {
        NSString *path1 = [NSString stringWithFormat:@"%s%s", jbroot, g_diagPaths[i]];
        [targetPaths addObject:path1];
        
        if (strcmp(jbroot, rootfs) != 0) {
            NSString *path2 = [NSString stringWithFormat:@"%s%s", rootfs, g_diagPaths[i]];
            [targetPaths addObject:path2];
        }
    }
    
    NSSet *uniquePaths = [NSSet setWithArray:targetPaths];
    
    NSUInteger deletedCount = 0;
    NSUInteger failedCount = 0;
    NSMutableArray *errors = [NSMutableArray array];
    
    for (NSString *path in uniquePaths) {
        // 跳过已知受保护路径
        if (mfShouldSkipPath(path)) {
            continue;
        }
        
        NSError *err = nil;
        BOOL isDir = NO;
        [[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir];
        
        if (isDir) {
            NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:path error:&err];
            if (contents) {
                for (NSString *item in contents) {
                    NSString *itemPath = [path stringByAppendingPathComponent:item];
                    // 跳过受保护子项
                    if (mfShouldSkipPath(itemPath)) continue;
                    
                    NSError *itemErr = nil;
                    if ([[NSFileManager defaultManager] removeItemAtPath:itemPath error:&itemErr]) {
                        deletedCount++;
                    } else {
                        failedCount++;
                        [errors addObject:[NSString stringWithFormat:@"%@: %@", itemPath, itemErr.localizedDescription]];
                    }
                }
            } else if (err) {
                failedCount++;
                [errors addObject:[NSString stringWithFormat:@"enum %@: %@", path, err.localizedDescription]];
            }
        } else {
            if ([[NSFileManager defaultManager] removeItemAtPath:path error:&err]) {
                deletedCount++;
            } else if (err && err.code != NSFileNoSuchFileError) {
                failedCount++;
                [errors addObject:[NSString stringWithFormat:@"%@: %@", path, err.localizedDescription]];
            }
        }
    }
    
    self.cleanupSuccess = (failedCount == 0);
    if (self.cleanupSuccess) {
        self.cleanupMessage = [NSString stringWithFormat:@"✅ 清理完成，共删除 %lu 项", (unsigned long)deletedCount];
    } else {
        self.cleanupMessage = [NSString stringWithFormat:@"⚠️ 部分清理失败 (%lu/%lu)，删除了 %lu 项\n错误:\n%@", 
                               (unsigned long)failedCount, (unsigned long)(deletedCount + failedCount), (unsigned long)deletedCount,
                               [errors componentsJoinedByString:@"\n"]];
    }
    
    // 回主线程显示结果
    [self performSelectorOnMainThread:@selector(showCleanupResult) withObject:nil waitUntilDone:NO];
}

- (void)showCleanupResult {
    [self.loadingAlert dismissViewControllerAnimated:YES completion:^{
        NSString *resultTitle = self.cleanupSuccess ? @"完成" : @"完成 (有失败)";
        UIAlertController *result = [UIAlertController alertControllerWithTitle:resultTitle
                                                                        message:self.cleanupMessage
                                                                 preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            [self.navigationController popViewControllerAnimated:YES];
        }];
        [result addAction:okAction];
        [self presentViewController:result animated:YES completion:nil];
    }];
}

@end
