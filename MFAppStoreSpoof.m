// MFAppStoreSpoof.m — AppStore 版本伪装
// hook appstored: 修改 User-Agent 里的 iOS 版本号
// hook installd: 绕过最低版本检查

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

static NSString *g_spoofVersion = nil;
static BOOL g_spoofEnabled = NO;

// v2.4.0 统一偏好域 com.linsars.minisfix(设置页「系统增强」分区),旧 appstoretroller 域作 fallback
static void loadConfig(void) {
    g_spoofVersion = @"99.0.0";
    g_spoofEnabled = NO;
    NSDictionary *p = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"];
    id en = p[@"mfSpoofEnabled"];
    if (en) {
        g_spoofEnabled = [en boolValue];
        NSString *v = p[@"mfSpoofVersion"];
        if (v.length > 0) g_spoofVersion = v;
        return;
    }
    // 兼容旧 appstoretroller 配置
    NSDictionary *old = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/dev.mineek.appstoretroller.plist"];
    NSNumber *enabled = old[@"enabled"];
    if (enabled && ![enabled boolValue]) return;
    NSString *ver = old[@"iOSVersion"];
    if (ver.length > 0) g_spoofVersion = ver;
    g_spoofEnabled = YES;
}

static BOOL isProcess(const char *name) {
    char path[1024];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    NSString *execPath = [NSString stringWithUTF8String:path];
    return [execPath hasSuffix:[NSString stringWithFormat:@"/%s", name]];
}

// hook 1: NSMutableURLRequest setValue:forHTTPHeaderField:
static void (*orig_setValue)(id self, SEL _cmd, NSString *value, NSString *field);
static void hook_setValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if ([field isEqualToString:@"User-Agent"] && [value containsString:@"iOS/"]) {
        NSRange range = [value rangeOfString:@"iOS/"];
        if (range.location != NSNotFound) {
            NSString *afterIOS = [value substringFromIndex:range.location + range.length];
            NSString *oldVersion = [[afterIOS componentsSeparatedByString:@" "] firstObject];
            NSString *oldFull = [NSString stringWithFormat:@"iOS/%@", oldVersion];
            NSString *newFull = [NSString stringWithFormat:@"iOS/%@", g_spoofVersion];
            NSString *modified = [value stringByReplacingOccurrencesOfString:oldFull withString:newFull];
            orig_setValue(self, _cmd, modified, field);
            return;
        }
    }
    orig_setValue(self, _cmd, value, field);
}

// hook 2: MIBundle 版本检查
static BOOL (*orig_isMinOS)(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err);
static BOOL hook_isMinOS(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err) {
    return YES;
}

static BOOL (*orig_isApplicable)(id self, SEL _cmd, NSError **err);
static BOOL hook_isApplicable(id self, SEL _cmd, NSError **err) {
    return YES;
}

extern void MFTestFlightHooksInstall(void);

// v2.4.0 AppHooks.dylib: 指定进程注入组(appstored/installd/TestFlight)
__attribute__((constructor))
static void AppHooks_init(void) {
    loadConfig();
    if (isProcess("TestFlight")) {
        MFTestFlightHooksInstall();
        return;
    }
    if (!g_spoofEnabled) return;

    if (isProcess("appstored")) {
        Class cls = objc_getClass("NSMutableURLRequest");
        if (cls) {
            Method m = class_getInstanceMethod(cls, @selector(setValue:forHTTPHeaderField:));
            if (m) {
                orig_setValue = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_setValue);
            }
        }
    } else if (isProcess("installd")) {
        Class cls = objc_getClass("MIBundle");
        if (cls) {
            // hook 多个版本检查方法
            Method m1 = class_getInstanceMethod(cls, @selector(_isMinimumOSVersion:applicableToOSVersion:requiredOS:error:));
            if (m1) {
                orig_isMinOS = (void *)method_getImplementation(m1);
                method_setImplementation(m1, (IMP)hook_isMinOS);
            }
            Method m2 = class_getInstanceMethod(cls, @selector(isMinimumOSVersion:applicableToOSVersion:error:));
            if (m2) {
                method_setImplementation(m2, (IMP)hook_isMinOS);
            }
            Method m3 = class_getInstanceMethod(cls, @selector(isApplicableToCurrentOSVersionWithError:));
            if (m3) {
                orig_isApplicable = (void *)method_getImplementation(m3);
                method_setImplementation(m3, (IMP)hook_isApplicable);
            }
        }
    }
}
