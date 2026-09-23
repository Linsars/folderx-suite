// SystemEnhanceController.m — 设置页「⚡️ 系统增强」子页(v2.4.0)
// 渲染 SystemEnhanceSettings.plist:版本伪装 / TF增强 / 诊断清理 / 充电限制 / Wi-Fi永连

#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>
#import <dlfcn.h>   // 兼容列表(AltList)需 dlopen AltList.framework

@interface SystemEnhanceController : PSListController
@end

@implementation SystemEnhanceController
- (NSArray *)specifiers {
    if (!_specifiers) {
        // AltList 是运行时 framework（不静态链接），需 dlopen 让 ATL 类可用 —
        // 否则兼容列表(ATLApplicationListMultiSelectionController)渲染不出，
        // 表现为"先逛一遍 IAP 工具箱的应用程序列表（那页 dlopen 过 AltList）再回来才显示"
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            dlopen("/var/jb/Library/Frameworks/AltList.framework/AltList", RTLD_LAZY);
        });
        _specifiers = [self loadSpecifiersFromPlistName:@"SystemEnhanceSettings" target:self];
    }
    return _specifiers;
}
@end
