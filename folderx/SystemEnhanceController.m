// SystemEnhanceController.m — 设置页「⚡️ 系统增强」子页(v2.4.0)
// 渲染 SystemEnhanceSettings.plist:版本伪装 / TF增强 / 诊断清理 / 充电限制 / Wi-Fi永连

#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>

@interface SystemEnhanceController : PSListController
@end

@implementation SystemEnhanceController
- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"SystemEnhanceSettings" target:self];
    }
    return _specifiers;
}
@end
