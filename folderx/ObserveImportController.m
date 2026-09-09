// ObserveImportController.m — 标本观察·导入 + 多选清单页(v2.55)
// 功能: 顶栏「导入」→ 文件 app(UIDocumentPicker)选 .dylib → 拷到 /var/mobile/minisfix/(mobile 可写)
//       主体 = 多选清单(每个 dylib 一个 PSSwitchTableCell, key=mfObserve_<文件名>)
//              + 「不装载任何」说明(全关 = 无标本不观察, 配合门控逻辑)
// 装载: CompatPatcher(mfFixcrashStage) 启动时扫 /var/mobile/minisfix/, 装 mfObserve_* = ON 的 dylib
// 说明: 目录实测 mobile 可读可写, 无需 root 通道。

#import <Preferences/PSListController.h>
#import <Preferences/PSTableCell.h>
#import <Preferences/PSSpecifier.h>
#import <Preferences/PSSwitchTableCell.h>
#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

#define kObserveDir @"/var/mobile/minisfix"
#define kObservePrefix @"mfObserve_"
#define kPrefsDomain @"com.linsars.minisfix"

@interface ObserveImportController : PSListController <UIDocumentPickerDelegate>
@end

@implementation ObserveImportController

- (NSArray *)specifiers {
    if (!_specifiers) {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *files = [fm contentsOfDirectoryAtPath:kObserveDir error:nil] ?: @[];
        NSMutableArray *arr = [NSMutableArray array];

        // 组: 说明(组 cell 无 state, 不传 get/set)
        PSSpecifier *grp = [PSSpecifier preferenceSpecifierNamed:@"标本装载(勾选要装载的)"
                                                          target:self
                                                             set:nil
                                                             get:nil
                                                          detail:nil
                                                            cell:PSGroupCell
                                                            edit:nil];
        [grp setProperty:@"勾选要在观察列表 App 中装载的标本, 全部不勾 = 不装载任何(无标本无法观察)。点右上「导入」从文件 App 选 dylib 拷入本目录。" forKey:@"footerText"];
        [arr addObject:grp];

        // 每个 dylib 一个开关; key = mfObserve_<文件名>; 全关 = 不装载任何
        NSUserDefaults *def = [[NSUserDefaults alloc] initWithSuiteName:kPrefsDomain];
        if (files.count == 0) {
            PSSpecifier *empty = [PSSpecifier preferenceSpecifierNamed:@"目录为空, 请先导入"
                                                                target:self
                                                                   set:nil
                                                                   get:nil
                                                                detail:nil
                                                                  cell:PSStaticTextCell
                                                                  edit:nil];
            [arr addObject:empty];
        }
        for (NSString *f in [files sortedArrayUsingSelector:@selector(compare)]) {
            if (![f.pathExtension isEqualToString:@"dylib"]) continue;
            PSSpecifier *sp = [PSSpecifier preferenceSpecifierNamed:f
                                                             target:self
                                                                set:@selector(setPreferenceValue:specifier:)
                                                                get:@selector(readPreferenceValue:)
                                                             detail:nil
                                                               cell:PSSwitchCell
                                                               edit:nil];
            [sp setProperty:[kObservePrefix stringByAppendingString:f] forKey:@"key"];
            [sp setProperty:kPrefsDomain forKey:@"defaults"];   // 让 cell 用 com.linsars.minisfix 域
            [arr addObject:sp];
        }

        _specifiers = arr;
    }
    return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    NSUserDefaults *def = [[NSUserDefaults alloc] initWithSuiteName:kPrefsDomain];
    return [def boolForKey:key] ? @YES : @NO;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    NSUserDefaults *def = [[NSUserDefaults alloc] initWithSuiteName:kPrefsDomain];
    if (key.length) [def setBool:[value boolValue] forKey:key];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    UIBarButtonItem *import = [[UIBarButtonItem alloc] initWithTitle:@"导入 dylib"
                                                               style:UIBarButtonItemStylePlain
                                                              target:self
                                                              action:@selector(pickDylib)];
    self.navigationItem.rightBarButtonItem = import;
}

- (void)pickDylib {
    UIDocumentPickerViewController *picker;
    if (@available(iOS 14.0, *)) {
        picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeData] asCopy:YES];
    } else {
        picker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.data"] inMode:UIDocumentPickerModeImport];
    }
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

#pragma mark - UIDocumentPickerDelegate
- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:kObserveDir]) [fm createDirectoryAtPath:kObserveDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *name = url.lastPathComponent;
    NSString *dest = [kObserveDir stringByAppendingPathComponent:name];
    NSError *err = nil;
    if ([fm fileExistsAtPath:dest]) [fm removeItemAtPath:dest error:nil];
    BOOL ok = [fm copyItemAtPath:url.path toPath:dest error:&err];
    if (!ok) ok = [fm moveItemAtPath:url.path toPath:dest error:&err];
    UIAlertController *al = [UIAlertController alertControllerWithTitle:@"导入标本"
                                                        message:(ok ? [NSString stringWithFormat:@"已从文件 App 拷贝到 %@", dest]
                                                                    : [NSString stringWithFormat:@"导入失败: %@", err.localizedDescription ?: @"?"])
                                                 preferredStyle:UIAlertControllerStyleAlert];
    [al addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){
        [self reloadSpecifiers];   // 刷新清单, 新导入的 dylib 立即出现
    }]];
    [self presentViewController:al animated:YES completion:nil];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    // 取消导入, 无操作
}

@end
