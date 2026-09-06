// MFTestFlightHooks.m — TestFlight 增强(编入 AppHooks.dylib,filter: TestFlight)
// 兼容性增强(mfTFCompatible): TFAppBuild compatible/platformCompatible/hardwareCompatible/minOSCompatible
// 禁止跑路(mfTFExpiration): expirationDate/setExpirationDate:
// v2.4.0 自 MFPanel.m 迁出——按注入目标归位:TF 是指定 App 注入,不属于全局面板 dylib

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#define TF_PREFS @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"

static BOOL tfPref(NSString *key, BOOL def) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:TF_PREFS];
    id v = d[key];
    return v ? [v boolValue] : def;
}

static void tf_swizzle(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (origOut) *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

static BOOL (*orig_tfCompatible)(id self, SEL _cmd);
static BOOL (*orig_tfPlatformCompatible)(id self, SEL _cmd);
static BOOL (*orig_tfHardwareCompatible)(id self, SEL _cmd);
static BOOL (*orig_tfMinOSCompatible)(id self, SEL _cmd);
static NSDate *(*orig_tfExpirationDate)(id self, SEL _cmd);
static void (*orig_tfSetExpirationDate)(id self, SEL _cmd, NSDate *date);

static BOOL hook_tfCompatible(id self, SEL _cmd) {
    return tfPref(@"mfTFCompatible", YES) ? YES : orig_tfCompatible ? orig_tfCompatible(self, _cmd) : YES;
}
static BOOL hook_tfPlatformCompatible(id self, SEL _cmd) {
    return tfPref(@"mfTFCompatible", YES) ? YES : orig_tfPlatformCompatible ? orig_tfPlatformCompatible(self, _cmd) : YES;
}
static BOOL hook_tfHardwareCompatible(id self, SEL _cmd) {
    return tfPref(@"mfTFCompatible", YES) ? YES : orig_tfHardwareCompatible ? orig_tfHardwareCompatible(self, _cmd) : YES;
}
static BOOL hook_tfMinOSCompatible(id self, SEL _cmd) {
    return tfPref(@"mfTFCompatible", YES) ? YES : orig_tfMinOSCompatible ? orig_tfMinOSCompatible(self, _cmd) : YES;
}
static NSDate *hook_tfExpirationDate(id self, SEL _cmd) {
    return tfPref(@"mfTFExpiration", YES) ? [NSDate distantFuture] : orig_tfExpirationDate ? orig_tfExpirationDate(self, _cmd) : [NSDate distantFuture];
}
static void hook_tfSetExpirationDate(id self, SEL _cmd, NSDate *date) {
    if (tfPref(@"mfTFExpiration", YES)) return;
    if (orig_tfSetExpirationDate) orig_tfSetExpirationDate(self, _cmd, date);
}

// 语义与原版一致: compatible 开 → 6 hook 全装(hook 内按各自开关分流);
// compatible 关 + expiration 开 → 只装 expiration 2 个
void MFTestFlightHooksInstall(void) {
    Class TFAppBuild = objc_getClass("TFAppBuild");
    if (!TFAppBuild) return;
    BOOL compat = tfPref(@"mfTFCompatible", YES);
    BOOL noExp = tfPref(@"mfTFExpiration", YES);

    if (compat) {
        tf_swizzle(TFAppBuild, @selector(compatible), (IMP)hook_tfCompatible, (IMP *)&orig_tfCompatible);
        tf_swizzle(TFAppBuild, @selector(platformCompatible), (IMP)hook_tfPlatformCompatible, (IMP *)&orig_tfPlatformCompatible);
        tf_swizzle(TFAppBuild, @selector(hardwareCompatible), (IMP)hook_tfHardwareCompatible, (IMP *)&orig_tfHardwareCompatible);
        tf_swizzle(TFAppBuild, @selector(minOSCompatible), (IMP)hook_tfMinOSCompatible, (IMP *)&orig_tfMinOSCompatible);
    }
    if (noExp) {
        tf_swizzle(TFAppBuild, @selector(expirationDate), (IMP)hook_tfExpirationDate, (IMP *)&orig_tfExpirationDate);
        tf_swizzle(TFAppBuild, @selector(setExpirationDate:), (IMP)hook_tfSetExpirationDate, (IMP *)&orig_tfSetExpirationDate);
    }
    NSLog(@"[AppHooks] TestFlight hooks installed (compat=%d noExp=%d)", compat, noExp);
}
