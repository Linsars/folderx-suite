// MFNetAnalyzer.m — 网络分析 (v1.7.1 瘦身版：捕获开关/捕获列表/规则管理/解密捕获)

#import "MFPanel.h"

#pragma mark - 页面

void mfShowNetAnalyzerPage(void) {
    UIView *page = mfMakePage(@"🌐 网络分析", YES);
    CGFloat gw = g_mfCardW - 32;

    // 顶部：实时捕获开关 + 捕获记录入口 + 规则管理入口
    UILabel *capLb = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, gw - 80, 24)];
    capLb.text = @"⏺ 实时捕获 HTTP(S)";
    capLb.font = [UIFont boldSystemFontOfSize:13];
    capLb.textColor = [UIColor labelColor];
    [page addSubview:capLb];
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(gw - 56, 44, 60, 31)];
    sw.on = mfCaptureEnabledState();
    objc_setAssociatedObject(sw, "key", @"mfCaptureEnabled", OBJC_ASSOCIATION_RETAIN);
    [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCaptureSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [page addSubview:sw];

    UIButton *listBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    listBtn.frame = CGRectMake(16, 84, gw, 42);
    listBtn.backgroundColor = [UIColor systemBlueColor];
    listBtn.layer.cornerRadius = 10;
    listBtn.tintColor = UIColor.whiteColor;
    listBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [listBtn setTitle:@"📡 打开捕获记录列表" forState:UIControlStateNormal];
    [listBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfShowNetworkCapturePage") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:listBtn];

    // 规则管理入口
    UIButton *ruleBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    ruleBtn.frame = CGRectMake(16, 134, gw, 42);
    ruleBtn.backgroundColor = [UIColor systemOrangeColor];
    ruleBtn.layer.cornerRadius = 10;
    ruleBtn.tintColor = UIColor.whiteColor;
    ruleBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [ruleBtn setTitle:@"🔧 规则管理（拦截/改包）" forState:UIControlStateNormal];
    [ruleBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfShowRuleManagerPage") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:ruleBtn];

    // 解密捕获入口（v1.9.3 自数据分析迁入——抓包场景同源）
    UIButton *decBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    decBtn.frame = CGRectMake(16, 184, gw, 42);
    decBtn.backgroundColor = [UIColor systemPurpleColor];
    decBtn.layer.cornerRadius = 10;
    decBtn.tintColor = UIColor.whiteColor;
    decBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [decBtn setTitle:@"🔓 解密捕获（CCCrypt/HMAC）" forState:UIControlStateNormal];
    [decBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfShowCryptoCapturePage") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:decBtn];

    mfPushPage(page);
}
