// MFPanel.m — IAP工具箱 v5.0 面板控制器 + 导航系统 + 主面板
// 主页双列网格：数据分析 📡 / Product 🛍️

#import "MFPanel.h"
#import <CommonCrypto/CommonCrypto.h>
#import <StoreKit/StoreKit.h>

// ====== 全局状态（定义在此，extern 在 MFPanel.h） ======
UIView *g_mfPanelOverlay = nil;
UIWindow *g_mfPanelWindow = nil;
UIViewController *g_mfPanelRootVC = nil;
id g_mfCtrl = nil;
NSMutableArray *g_mfPages = nil;
CGFloat g_mfCardW = 0, g_mfCardH = 0;
UIView *g_mfCardContentView = nil;  // card.contentView——子页挂这里
UIView *g_mfHomePage = nil;         // 主页内容容器——push 子页时隐藏
UIVisualEffectView *g_mfCardView = nil;  // 卡片引用——动态伸缩用
CGFloat g_mfHomeCardH = 300;        // 主页卡片高度

// ====== 日志 ======
void mfLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[MF] %@", msg);
    // 写沙盒日志
    static NSString *logPath = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        logPath = [docs stringByAppendingPathComponent:@"mf_debug.log"];
    });
    @try {
        NSString *line = [NSString stringWithFormat:@"[%.0f] %@\n", [NSDate date].timeIntervalSince1970, msg];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
        if (!fh) {
            [[NSFileManager defaultManager] createFileAtPath:logPath contents:nil attributes:nil];
            fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
        }
        if (fh) { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    } @catch (NSException *e) {}
}

// ====== Prefs ======
NSDictionary *mfPrefsDict(void) {
    static NSString *path = nil;
    if (!path) path = @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist";
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:path];
    return d ?: @{};
}

// 设置页启用检查：启用 IAP工具箱（mfIAPEnabled，默认开）× 应用程序白名单（mfIAPAppList，
// AltList 多选存启用数组；空=不启用任何 app）。所有更改需 respring 生效（ctor 只跑一次）。
BOOL mfIsEnabledForCurrentApp(void) {
    NSDictionary *prefs = mfPrefsDict();
    NSNumber *en = prefs[@"mfIAPEnabled"];
    if (en && ![en boolValue]) return NO;
    // 自动添加开启 = 所有 app 生效，不检查白名单
    if (mfPrefBool(@"mfIAPAutoApply", YES)) return YES;
    // 自动添加关闭 = 只对白名单内的 app 生效
    NSArray *wl = prefs[@"mfIAPAppList"];
    if (![wl isKindOfClass:[NSArray class]] || wl.count == 0) return NO;
    return [wl containsObject:[[NSBundle mainBundle] bundleIdentifier]];
}
void mfSetPrefs(NSDictionary *d) {
    [d writeToFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist" atomically:YES];
}
BOOL mfPrefBool(NSString *key, BOOL def) {
    id v = mfPrefsDict()[key];
    return v ? [v boolValue] : def;
}
void mfSetBoolPref(NSString *key, BOOL val) {
    NSMutableDictionary *d = [mfPrefsDict() mutableCopy];
    d[key] = @(val);
    mfSetPrefs(d);
}
void mfSetPrefDouble(NSString *key, double val) {
    NSMutableDictionary *d = [mfPrefsDict() mutableCopy];
    d[key] = @(val);
    mfSetPrefs(d);
}
double mfPrefDouble(NSString *key, double def) {
    id v = mfPrefsDict()[key];
    return v ? [v doubleValue] : def;
}

// ====== 网络捕获状态（MFNetworkCapture.m 里的全局变量，用 extern 或直接声明） ======
extern BOOL g_captureEnabled;
extern BOOL g_rewriteEnabled;
extern NSMutableArray *g_rewriteRules;
extern void mfLoadRules(void);
extern void mfSaveRules(void);
extern void mfAddRule(NSString *pattern, NSString *matchType, NSString *action);

// ====== 页面导航 ======
UIView *mfMakePage(NSString *title, BOOL showBack) {
    // 子页统一拉长卡片（主页不经过这里）
    if (g_mfPanelOverlay) {
        CGFloat maxH = MIN(560, g_mfPanelOverlay.bounds.size.height - 100);
        if (g_mfCardH < maxH) mfSetCardHeight(maxH);
    }
    UIView *page = [[UIView alloc] initWithFrame:CGRectMake(0, 0, g_mfCardW, g_mfCardH)];
    page.backgroundColor = [UIColor clearColor];
    UIView *nav = [[UIView alloc] initWithFrame:CGRectMake(0, 0, g_mfCardW, 40)];
    [page addSubview:nav];
    if (showBack) {
        UIButton *back = [UIButton buttonWithType:UIButtonTypeSystem];
        back.frame = CGRectMake(6, 4, 64, 32);
        [back setTitle:@"‹ 返回" forState:UIControlStateNormal];
        back.titleLabel.font = [UIFont systemFontOfSize:15];
        [back addTarget:g_mfCtrl action:NSSelectorFromString(@"mfPopPage") forControlEvents:UIControlEventTouchUpInside];
        [nav addSubview:back];
    }
    UILabel *t = [[UILabel alloc] initWithFrame:CGRectMake(60, 6, g_mfCardW - 120, 28)];
    t.text = title;
    t.font = [UIFont boldSystemFontOfSize:16];
    t.textAlignment = NSTextAlignmentCenter;
    t.textColor = [UIColor labelColor];
    [nav addSubview:t];
    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.frame = CGRectMake(g_mfCardW - 40, 4, 32, 32);
    [close setTitle:@"✕" forState:UIControlStateNormal];
    [close addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClosePanel") forControlEvents:UIControlEventTouchUpInside];
    [nav addSubview:close];
    return page;
}

// 动态调整卡片高度（子页拉长 / 主页恢复紧凑）
// 通用轻提示：keyWindow 浮层，1.4s 自动淡出
void mfToast(NSString *msg) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win = nil;
        for (UIWindow *w in [UIApplication sharedApplication].windows)
            if (w.isKeyWindow) { win = w; break; }
        if (!win) return;
        UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(20, win.bounds.size.height - 160, win.bounds.size.width - 40, 40)];
        lb.text = msg;
        lb.font = [UIFont boldSystemFontOfSize:14];
        lb.textAlignment = NSTextAlignmentCenter;
        lb.textColor = UIColor.whiteColor;
        lb.backgroundColor = [UIColor colorWithWhite:0 alpha:0.82];
        lb.layer.cornerRadius = 12;
        lb.layer.masksToBounds = YES;
        lb.tag = 918273;
        // 已有 toast 先撤
        for (UIView *v in win.subviews) if (v.tag == 918273) [v removeFromSuperview];
        [win addSubview:lb];
        lb.alpha = 0;
        [UIView animateWithDuration:0.18 animations:^{ lb.alpha = 1; } completion:^(BOOL f) {
            [UIView animateWithDuration:0.25 delay:1.15 options:UIViewAnimationOptionCurveEaseIn animations:^{
                lb.alpha = 0;
                lb.transform = CGAffineTransformMakeTranslation(0, -10);
            } completion:^(BOOL f2) { [lb removeFromSuperview]; }];
        }];
    });
}

void mfSetCardHeight(CGFloat h) {
    if (!g_mfCardView || !g_mfPanelOverlay) return;
    CGRect sb = g_mfPanelOverlay.bounds;
    CGRect f = g_mfCardView.frame;
    f.size.height = h;
    f.origin.y = (sb.size.height - h) / 2;
    g_mfCardView.frame = f;
    g_mfCardH = h;
    g_mfCardContentView.frame = CGRectMake(0, 0, f.size.width, h);
    mfLog(@"card height -> %.0f", h);
}

void mfPushPage(UIView *page) {
    if (!g_mfPages) g_mfPages = [[NSMutableArray alloc] init];
    // 隐藏主页和所有已存在子页
    if (g_mfHomePage) g_mfHomePage.hidden = YES;
    for (UIView *p in g_mfPages) p.hidden = YES;
    // 子页自动拉长卡片（最高 560 或屏高-100）
    if (g_mfPanelOverlay) {
        CGFloat maxH = MIN(560, g_mfPanelOverlay.bounds.size.height - 100);
        if (g_mfCardH < maxH) mfSetCardHeight(maxH);
    }
    page.frame = CGRectMake(0, 0, g_mfCardW, g_mfCardH);
    UIView *container = g_mfCardContentView ?: g_mfPanelOverlay;
    [container addSubview:page];
    [g_mfPages addObject:page];
}

void mfPopPage(void) {
    if (g_mfPages.count == 0) return;
    UIView *top = [g_mfPages lastObject];
    [top removeFromSuperview];
    [g_mfPages removeLastObject];
    if (g_mfPages.count > 0) {
        [[g_mfPages lastObject] setHidden:NO];
        // 子页还在——保持拉长
    } else if (g_mfHomePage) {
        g_mfHomePage.hidden = NO;
        // 回主页——恢复紧凑高度
        if (g_mfHomeCardH > 0) mfSetCardHeight(g_mfHomeCardH);
        if (g_mfHomePage) g_mfHomePage.frame = g_mfCardContentView.bounds;
    }
}

void mfClosePanel(void) {
    if (g_mfPanelOverlay) {
        UIView *ov = g_mfPanelOverlay;
        [UIView animateWithDuration:0.2 animations:^{ ov.alpha = 0; } completion:^(BOOL f) {
            [ov removeFromSuperview];
            g_mfPanelWindow.hidden = YES; // v2.6.2
            g_mfPanelOverlay = nil;
            g_mfPanelRootVC = nil;
            g_mfCardContentView = nil;
            g_mfHomePage = nil;
            g_mfCardView = nil;
            [g_mfPages removeAllObjects];
            mfLog(@"panel: closed");
        }];
    }
}

// ====== 网格按钮工具 ======
// v2.7.1: 通用键盘收起工具条——所有手动输入框统一挂载（target=输入框自身 resignFirstResponder，零转发）
void mfAttachKbBar(id field) {
    if (![field respondsToSelector:@selector(setInputAccessoryView:)]) return;
    UIToolbar *bar = [[UIToolbar alloc] initWithFrame:CGRectMake(0, 0, g_mfCardW, 44)];
    UIBarButtonItem *flex = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil];
    UIBarButtonItem *done = [[UIBarButtonItem alloc] initWithTitle:@"⌨️ 收起" style:UIBarButtonItemStyleDone target:field action:@selector(resignFirstResponder)];
    bar.items = @[flex, done];
    if ([field isKindOfClass:[UITextField class]]) ((UITextField *)field).inputAccessoryView = bar;
    else ((UITextView *)field).inputAccessoryView = bar;
}

// v2.7.2: 通用剪贴板复制（+可选 toast）
void mfCopyText(NSString *text, NSString *toastMsg) {
    if (!text.length) return;
    [UIPasteboard generalPasteboard].string = text;
    if (toastMsg.length) mfToast(toastMsg);
}

// v2.7.2: 最顶层 VC 定位——keyWindow 查找 + presented 链遍历，全插件统一
UIViewController *mfTopVC(void) {
    UIWindow *win = nil;
    for (UIWindow *w in [UIApplication sharedApplication].windows)
        if (!w.hidden && w.rootViewController) { win = w; if (w.isKeyWindow) break; }
    if (!win) return nil;
    UIViewController *vc = win.rootViewController;
    while (vc.presentedViewController && ![vc.presentedViewController isBeingDismissed])
        vc = vc.presentedViewController;
    return vc;
}

// v2.7.2: 通用行按钮——消灭 6-8 行样板
UIButton *mfRowButton(UIView *parent, CGFloat x, CGFloat y, CGFloat w, CGFloat h,
                      NSString *title, UIColor *bg, SEL action) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = CGRectMake(x, y, w, h);
    b.backgroundColor = bg;
    b.layer.cornerRadius = 10;
    b.tintColor = UIColor.whiteColor;
    b.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [b setTitle:title forState:UIControlStateNormal];
    if (action) [b addTarget:g_mfCtrl action:action forControlEvents:UIControlEventTouchUpInside];
    [parent addSubview:b];
    return b;
}

CGFloat mfGridButton(UIView *card, CGFloat x, CGFloat y, CGFloat w, NSString *title, NSString *emoji, SEL action, BOOL switchMode, NSString *pfx) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = CGRectMake(x, y, w, 84);
    b.backgroundColor = [UIColor secondarySystemBackgroundColor];
    b.layer.cornerRadius = 16;
    [b addTarget:g_mfCtrl action:action forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:b];
    UILabel *ic = [[UILabel alloc] initWithFrame:CGRectMake(0, 10, w, 44)];
    ic.text = emoji;
    ic.font = [UIFont systemFontOfSize:24];
    ic.textAlignment = NSTextAlignmentCenter;
    ic.userInteractionEnabled = NO;
    [b addSubview:ic];
    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(0, 58, w, 18)];
    lb.text = title;
    lb.font = [UIFont systemFontOfSize:12];
    lb.textAlignment = NSTextAlignmentCenter;
    lb.textColor = [UIColor labelColor];
    lb.adjustsFontSizeToFitWidth = YES;
    lb.minimumScaleFactor = 0.7;
    lb.userInteractionEnabled = NO;
    [b addSubview:lb];
    if (switchMode && pfx) {
        BOOL on = mfPrefBool(pfx, NO);
        b.backgroundColor = on ? [UIColor systemGreenColor] : [UIColor secondarySystemBackgroundColor];
        objc_setAssociatedObject(b, "pfx", pfx, OBJC_ASSOCIATION_RETAIN);
    }
    return y + 92;
}

// ====== 功能页面入口（转发到各模块） ======
// 页面函数（各模块 .m 定义——extern 到 MFPanel.h）
void mfShowDataAnalysisPage(void);  // MFNetworkCapture.m
void mfShowNetworkCapturePage(void); // MFNetworkCapture.m
void mfShowCryptoToolboxPage(void);  // MFNetworkCapture.m
void mfShowNetworkModifyPage(void);  // MFNetworkCapture.m
void mfShowHostLogPage(void);        // MFPanel.m 本文件 (v2.6.17)
// v2.6.17 宿主日志引擎 (MFHostLogCapture.m) —— 必须在调用点之前声明(隐式 int 会与定义冲突)
extern void mfHostLogStart(void);
extern void mfHostLogStop(void);
extern BOOL mfHostLogRunning(void);
extern unsigned long long mfHostLogBufferedCount(void);
extern unsigned long long mfHostLogTotal(void);
extern NSArray<NSString *> *mfHostLogSnapshot(void);
extern void mfHostLogClear(void);
// v2.6.21 电池详情 (MFBatteryInfo.m)
extern NSDictionary *mfBatteryRead(void);
extern void mfShowBatteryPage(void);

// ====== 本地二进制扫描 ======
// 前向声明

// ====== PID 形态判定(v2.0.3):不限 com. 前缀——反向域名与下划线 slug 都收 ======
// 必须含 IAP 语义关键词或匹配 bundleId 主机段,否则二进制点分字符串噪声爆炸
static BOOL mfPIDShaped(NSString *s) {
    if (s.length < 6 || s.length > 80) return NO;
    // v2.6.5: C 符号噪音排除——_pthread_rwlock_unlock/_lck_txn_unlock 类
    if ([s hasPrefix:@"_"]) return NO;
    NSCharacterSet *ok = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"];
    if ([s rangeOfCharacterFromSet:ok.invertedSet].location != NSNotFound) return NO;
    if (![s containsString:@"."] && ![s containsString:@"_"] && ![s containsString:@"-"]) return NO;
    NSString *low = s.lowercaseString;
    // 按分隔符切段后整段匹配——containsString 会把 processing/provider 这类子串全放进来(v2.1.0 教训: 12627 候选)
    static NSArray *segKws = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        segKws = @[@"iap", @"iaps", @"purchase", @"premium", @"pro", @"vip", @"plus",
            @"unlock", @"unlocked", @"lifetime", @"donate", @"donation", @"subs",
            @"subscription", @"weekly", @"monthly", @"yearly", @"annual", @"gold",
            @"coins", @"gem", @"gems", @"credit", @"credits", @"token", @"tokens",
            @"pack", @"upgrade", @"member", @"tier", @"supporter", @"byok", @"perks"];
    });
    NSArray *parts = [low componentsSeparatedByCharactersInSet:
        [[NSCharacterSet alphanumericCharacterSet] invertedSet]];
    // v2.6.5: 全大写段噪音排除——AWS_SESSION_TOKEN/ERROR_MISSING_TOKEN 类常量
    // (必须用原始串切段;low 是小写化的,永远不等于自己的大写版本)
    if ([s rangeOfCharacterFromSet:[NSCharacterSet uppercaseLetterCharacterSet]].location != NSNotFound) {
        NSArray *rawParts = [s componentsSeparatedByCharactersInSet:
            [[NSCharacterSet alphanumericCharacterSet] invertedSet]];
        BOOL allUpper = YES;
        for (NSString *p in rawParts) {
            if (p.length < 2) continue;
            if (![p isEqualToString:p.uppercaseString]) { allUpper = NO; break; }
        }
        if (allUpper) return NO;
    }
    for (NSString *part in parts) {
        if (part.length >= 3 && [segKws containsObject:part]) return YES;
    }
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    NSArray *seg = [bid componentsSeparatedByString:@"."];
    if (seg.count >= 2) {
        NSString *host = [[NSString stringWithFormat:@"%@.%@", seg[0], seg[1]] lowercaseString];
        if ([low hasPrefix:host]) return YES;
    }
    return NO;
}
static BOOL mfPIDExcluded(NSString *s) {
    return [s hasPrefix:@"com.apple."] || [s hasPrefix:@"com.facebook."] ||
           [s hasPrefix:@"com.google."] || [s hasPrefix:@"com.adjust."] ||
           [s hasPrefix:@"com.appsflyer."] || [s hasPrefix:@"com.branch."];
}
static NSSet *mfScanFileForPIDs(NSString *path);
static void mfQueryLocalPrices(NSArray *pids, void (^cb)(NSDictionary *pidToPrice, NSDictionary *pidToTitle));
static NSMutableSet *g_mfRCKeys = nil; // v2.6.4: RevenueCat public key 静态收集池
static NSMutableSet *g_mfSlugTokens = nil; // v2.6.8: 运行时拼接 ID 的片段池(纯小写+下划线,无点)

// 从 Mach-O 的 __cstring 段提取 product ID（只匹配 bundleId. 前缀）

// ====== 从捕获记录响应体提取 productId(v1.9.9 通用主路径) ======
// 现代 App 内购列表由自家服务器下发(价格/文案/ID 打包成 JSON),
// HTTP 层截获即得——不依赖 StoreKit 版本,对所有 App 生效
static NSArray *mfExtractPIDsFromCaptures(void) {
    NSMutableOrderedSet *out = [NSMutableOrderedSet orderedSet];
    NSArray *recs = mfCapturedRecordsSnapshot();
    NSError *reErr = nil;
    // 键名形态: product_id / productId / productIdentifier / iap_id / platform_product_identifier(v2.6.4 RevenueCat) …
    NSRegularExpression *re = [NSRegularExpression
        regularExpressionWithPattern:@"\"((?:platform_)?product[_]?(?:[iI]d|identifier)|iap[_]?id|purchase[_]?id)\"\\s*:\\s*\"([^\"\\\\]{4,80})\""
        options:NSRegularExpressionCaseInsensitive error:&reErr];
    // 兜底形态:任意 "id"/"identifier" 键下挂反向域名样式值(products 数组常用)
    NSRegularExpression *re2 = [NSRegularExpression
        regularExpressionWithPattern:@"\"(id|identifier)\":\"((?:com|app|net|io|org)\\.[A-Za-z0-9_.\\-/]{4,70})\""
        options:NSRegularExpressionCaseInsensitive error:nil];
    __block unsigned bodies = 0;
    for (MFNetRecord *r in recs) {
        NSMutableString *both = [NSMutableString string];
        NSString *b1 = [[NSString alloc] initWithData:r.respBody encoding:NSUTF8StringEncoding];
        if (b1) [both appendString:b1];
        NSString *b2 = [[NSString alloc] initWithData:r.reqBody encoding:NSUTF8StringEncoding];
        if (b2) [both appendFormat:@"\n%@", b2];
        if (both.length < 8) continue;
        bodies++;
        for (NSRegularExpression *rx in @[re, re2]) {
            [rx enumerateMatchesInString:both options:0 range:NSMakeRange(0, both.length)
                usingBlock:^(NSTextCheckingResult *m, NSMatchingFlags flags, BOOL *stop) {
                    NSUInteger gi = m.numberOfRanges > 2 ? 2 : 1;
                    if ([m rangeAtIndex:gi].location == NSNotFound) return;
                    NSString *pid = [both substringWithRange:[m rangeAtIndex:gi]];
                    if (pid.length >= 4 && pid.length <= 80) [out addObject:pid];
                }];
        }
    }
    mfLog(@"[iap] net-scan bodies=%lu/%lu extracted=%lu", (unsigned long)bodies, (unsigned long)recs.count, (unsigned long)out.count);
    return out.array;
}


static NSArray *mfScanLocalProductIDs(void) {
    NSMutableSet *found = [NSMutableSet set];
    NSString *exePath = [[NSBundle mainBundle] executablePath];
    if (exePath) [found unionSet:mfScanFileForPIDs(exePath)];
    NSString *fwDir = [[NSBundle mainBundle] privateFrameworksPath];
    if (fwDir) {
        for (NSString *fw in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:fwDir error:nil]) {
            if ([fw hasSuffix:@".framework"]) {
                NSString *name = [fw stringByDeletingPathExtension];
                NSString *fwBin = [fwDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/%@", fw, name]];
                [found unionSet:mfScanFileForPIDs(fwBin)];
            }
        }
    }
    NSString *pluginDir = [[NSBundle mainBundle] builtInPlugInsPath];
    if (pluginDir) {
        for (NSString *ext in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:pluginDir error:nil]) {
            if ([ext hasSuffix:@".appex"]) {
                NSString *extExe = [pluginDir stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"%@/%@", ext, [ext stringByDeletingPathExtension]]];
                [found unionSet:mfScanFileForPIDs(extExe)];
            }
        }
    }
    // v2.2.3: SK2 产品目录磁盘缓存——Library/Caches 下递归扫小文件(含 StoreKit/storeservicesd 缓存)
    NSString *cacheRoot = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES)[0];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSURL *> *queue = [NSMutableArray arrayWithObject:[NSURL fileURLWithPath:cacheRoot]];
    int files = 0;
    while (queue.count && files < 400) {
        NSURL *dirURL = [queue firstObject];
        [queue removeObjectAtIndex:0];
        NSArray *items = [fm contentsOfDirectoryAtURL:dirURL includingPropertiesForKeys:@[NSURLFileSizeKey, NSURLIsDirectoryKey] options:NSDirectoryEnumerationSkipsHiddenFiles error:nil];
        for (NSURL *u in items) {
            NSNumber *isDir = nil, *size = nil;
            [u getResourceValue:&isDir forKey:NSURLIsDirectoryKey error:nil];
            [u getResourceValue:&size forKey:NSURLFileSizeKey error:nil];
            if ([isDir boolValue]) { [queue addObject:u]; continue; }
            unsigned long long sz = size.unsignedLongLongValue;
            if (sz == 0 || sz > 4 * 1024 * 1024) continue;
            [found unionSet:mfScanFileForPIDs(u.path)];
            files++;
            if (files >= 400) break;
        }
    }
    mfLog(@"[iap] cache sweep: %d files from %@", files, cacheRoot.lastPathComponent);
    return [[found allObjects] sortedArrayUsingSelector:@selector(compare:)];
}



// 扫描单个文件：提取所有 com.xxx.xxx.xxx 格式的字符串（3段以上点分）
// 后续由 SKProductsRequest 验证哪些是真正的 product ID
// v2.6.5: RC public key 判定——appl_ + base62,总长 20-60(实测 32: appl_+27,勿再写死 44)
static BOOL mfIsRCPublicKey(NSString *s) {
    if (s.length < 20 || s.length > 60) return NO;
    if (![s hasPrefix:@"appl_"]) return NO;
    static NSCharacterSet *b62 = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        b62 = [NSCharacterSet characterSetWithCharactersInString:
            @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"];
    });
    return [[s substringFromIndex:5] rangeOfCharacterFromSet:b62.invertedSet].location == NSNotFound;
}

static NSSet *mfScanFileForPIDs(NSString *path) {
    NSMutableSet *pids = [NSMutableSet set];
    if (!g_mfRCKeys) g_mfRCKeys = [NSMutableSet set];
    if (!g_mfSlugTokens) g_mfSlugTokens = [NSMutableSet set];
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (!data.length) return pids;
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger len = data.length;
    NSMutableString *current = [NSMutableString string];
    for (NSUInteger i = 0; i < len; i++) {
        uint8_t c = bytes[i];
        if (c >= 0x20 && c < 0x7F) {
            [current appendFormat:@"%c", c];
        } else {
            // v2.6.4: RevenueCat public SDK key 顺带收集——offerings 查询入口
            if (mfIsRCPublicKey(current)) [g_mfRCKeys addObject:[current copy]];
            // v2.6.8: 拼接片段收集——运行时构造的 ID(pythonide 模式: "donate_"+item)在二进制里只有片段
            if (current.length >= 4 && current.length <= 24 && g_mfSlugTokens.count < 300) {
                BOOL slugOK = ![current hasPrefix:@"_"] && ![current hasSuffix:@"_"]
                    && [current rangeOfString:@"__"].location == NSNotFound
                    && [current rangeOfString:@"."].location == NSNotFound;
                if (slugOK) {
                    for (NSUInteger j = 0; j < current.length; j++) {
                        char ch = [current characterAtIndex:j];
                        if (!((ch >= 'a' && ch <= 'z') || ch == '_')) { slugOK = NO; break; }
                    }
                    if (slugOK) [g_mfSlugTokens addObject:[current copy]];
                }
            }
            // v2.6.11: JSON 配置数组形态——"iaps":["id1","id2"](Swiftgram 编译期注入模式,通用: 任意 xxxs 键)
            // 必须在 PIDShaped 之前: 数组串含引号/方括号,会被形态过滤拒掉
            if (current.length >= 12 && [current rangeOfString:@"\":["].location != NSNotFound) {
                NSError *je = nil;
                NSRegularExpression *jrx = [NSRegularExpression
                    regularExpressionWithPattern:@"\"[a-z_]{2,24}\":\\[([^\\[\\]]{4,600})\\]"
                    options:0 error:&je];
                [jrx enumerateMatchesInString:current options:0 range:NSMakeRange(0, current.length)
                    usingBlock:^(NSTextCheckingResult *jm, NSMatchingFlags jf, BOOL *js) {
                        NSString *arrBody = [current substringWithRange:[jm rangeAtIndex:1]];
                        NSRegularExpression *erx = [NSRegularExpression
                            regularExpressionWithPattern:@"\"([A-Za-z0-9._-]{4,80})\"" options:0 error:nil];
                        [erx enumerateMatchesInString:arrBody options:0 range:NSMakeRange(0, arrBody.length)
                            usingBlock:^(NSTextCheckingResult *em, NSMatchingFlags ef, BOOL *es) {
                                NSString *el = [arrBody substringWithRange:[em rangeAtIndex:1]];
                                if (mfPIDShaped(el) && !mfPIDExcluded(el)) [pids addObject:el];
                            }];
                    }];
            }
            if (current.length >= 6 && mfPIDShaped(current)) {
                NSString *sv = [current copy];
                if (!mfPIDExcluded(sv)) [pids addObject:sv];
            }
            [current setString:@""];
        }
    }
    if (mfIsRCPublicKey(current)) [g_mfRCKeys addObject:[current copy]];
    if (current.length >= 6 && mfPIDShaped(current) && !mfPIDExcluded(current)) {
        [pids addObject:[current copy]];
    }
    return pids;
}

// v2.6.4: RevenueCat 路径——静态挖 public key(appl_) → offerings API 拿全量 productId
// offerings 响应 offerings[].packages[].platform_product_identifier 是开发者配置的完整商品列表,
// slug 形态 ID(live_level_subscription_monthly)静态扫描易漏,此处一网打尽
static NSSet *mfCollectedRCKeys(void) { return g_mfRCKeys ?: [NSSet set]; }

// v2.6.8: 片段组合候选——语义前缀 × 二进制片段,喂 SK 裁决
// 依据: pythonide 的 unlock_/byok_ 实锤拼接构造;组合命中靠 Apple 验证兜底,无效 ID 静默忽略
static NSArray *mfComboCandidates(void) {
    if (!g_mfSlugTokens.count) return @[];
    NSMutableOrderedSet *prefixes = [NSMutableOrderedSet orderedSetWithArray:@[
        @"byok", @"pro", @"premium", @"donate", @"feed", @"ssh", @"unlock", @"iap",
        @"purchase", @"buy", @"vip", @"plus", @"pack", @"credit", @"coin", @"gem",
        @"member", @"tier", @"upgrade", @"lifetime", @"subscription", @"subs", @"gold"]];
    // app 名前缀动态加(pythonide_pro_monthly 形态)
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    NSArray *bseg = [bid componentsSeparatedByString:@"."];
    if (bseg.count) [prefixes addObject:[(NSString *)bseg.lastObject lowercaseString]];
    NSMutableOrderedSet *out = [NSMutableOrderedSet orderedSet];
    for (NSString *p in prefixes) {
        for (NSString *t in g_mfSlugTokens) {
            if (out.count >= 400) return out.array;
            if ([t hasPrefix:p] || [t hasSuffix:p]) continue; // 避免重复语义
            [out addObject:[NSString stringWithFormat:@"%@_%@", p, t]];
        }
    }
    return out.array;
}

// v2.6.7: 商品名 → productId 猜测生成器
// 依据: byok_unlock_permanent 实锤 slug 命名习惯;商品名 slug 化 + 段裁剪变体
// SKProductsRequest 是唯一裁判(SK1/SK2 商品库同源),无效 ID 静默忽略
static NSArray *mfGuessIDsFromTitles(NSArray *titles) {
    NSMutableOrderedSet *out = [NSMutableOrderedSet orderedSet];
    NSCharacterSet *sep = [[NSCharacterSet alphanumericCharacterSet] invertedSet];
    for (NSString *t in titles) {
        NSArray *parts = [[t.lowercaseString componentsSeparatedByCharactersInSet:sep]
            filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"SELF.length > 0"]];
        if (!parts.count) continue;
        // 全拼接: pythonide_pro_monthly
        [out addObject:[parts componentsJoinedByString:@"_"]];
        // 去第一段(去 app 名): pro_monthly
        if (parts.count > 1)
            [out addObject:[[parts subarrayWithRange:NSMakeRange(1, parts.count-1)] componentsJoinedByString:@"_"]];
        // 去尾段(去周期后缀): pythonide_pro
        if (parts.count > 1)
            [out addObject:[[parts subarrayWithRange:NSMakeRange(0, parts.count-1)] componentsJoinedByString:@"_"]];
        // 去前两段: monthly
        if (parts.count > 2)
            [out addObject:[[parts subarrayWithRange:NSMakeRange(2, parts.count-2)] componentsJoinedByString:@"_"]];
    }
    NSMutableArray *clean = [NSMutableArray array];
    for (NSString *g in out) {
        if (g.length >= 5 && g.length <= 80 && ![g hasPrefix:@"_"] && ![g hasSuffix:@"_"])
            [clean addObject:g];
    }
    return [clean copy];
}

// v2.6.12: bundleId → trackId（缓存）
static void mfLookupTrackId(NSString *bundleId, void (^cb)(NSString *)) {
    NSString *ck = [NSString stringWithFormat:@"trackId_%@", bundleId];
    NSString *cached = [[NSUserDefaults standardUserDefaults] stringForKey:ck];
    if (cached.length) { cb(cached); return; }
    NSString *lk = [NSString stringWithFormat:@"https://itunes.apple.com/lookup?bundleId=%@", bundleId];
    [[NSURLSession.sharedSession dataTaskWithURL:[NSURL URLWithString:lk]
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSString *trackId = nil;
            if (d.length > 10) {
                NSString *body = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                NSError *er = nil;
                NSRegularExpression *rx = [NSRegularExpression
                    regularExpressionWithPattern:@"\"trackId\":(\\d{6,12})" options:0 error:&er];
                NSTextCheckingResult *m = [rx firstMatchInString:body options:0 range:NSMakeRange(0, body.length)];
                if (m) trackId = [body substringWithRange:[m rangeAtIndex:1]];
            }
            if (trackId.length) [[NSUserDefaults standardUserDefaults] setObject:trackId forKey:ck];
            cb(trackId);
    }] resume];
}

// v2.6.13: 档案库查询——自建库优先(数据自主),AppForge 公开库 fallback;结果均缓存
static NSString * const mfArchiveSelf = @"https://pid-archive.linsar.de5.net";
static void mfFetchArchiveIDsOnce(NSString *base, NSString *trackId, BOOL quiet, void (^cb)(NSArray *)) {
    NSString *u = [NSString stringWithFormat:@"%@/v1/apps/%@/product-ids", base, trackId];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:u]];
    req.timeoutInterval = 10;
    [[NSURLSession.sharedSession dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSMutableArray *ids = [NSMutableArray array];
            if (d.length > 20) {
                NSString *body = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                NSRange pr = [body rangeOfString:@"\"productIds\":["];
                if (pr.location != NSNotFound) {
                    NSRange end = [body rangeOfString:@"]" options:0 range:NSMakeRange(pr.location + pr.length, MIN((NSUInteger)4000, body.length - pr.location - pr.length))];
                    if (end.location != NSNotFound) {
                        NSString *arr = [body substringWithRange:NSMakeRange(pr.location + pr.length, end.location - pr.location - pr.length)];
                        NSError *er = nil;
                        NSRegularExpression *rx = [NSRegularExpression
                            regularExpressionWithPattern:@"\"([A-Za-z0-9._-]{4,80})\"" options:0 error:&er];
                        [rx enumerateMatchesInString:arr options:0 range:NSMakeRange(0, arr.length)
                            usingBlock:^(NSTextCheckingResult *m, NSMatchingFlags f, BOOL *s) {
                                [ids addObject:[arr substringWithRange:[m rangeAtIndex:1]]];
                            }];
                    }
                }
            }
            cb(ids.count ? ids : nil);
    }] resume];
}
static void mfFetchArchiveIDs(NSString *trackId, void (^cb)(NSArray *)) {
    if (!trackId.length) { cb(nil); return; }
    NSString *ck = [NSString stringWithFormat:@"archiveIDs_%@", trackId];
    NSArray *cached = [[NSUserDefaults standardUserDefaults] objectForKey:ck];
    if (cached.count) { mfLog(@"[iap] archive: cache %lu ids", (unsigned long)cached.count); cb(cached); return; }
    // 自建库优先
    mfFetchArchiveIDsOnce(mfArchiveSelf, trackId, NO, ^(NSArray *selfIds) {
        if (selfIds.count) {
            [[NSUserDefaults standardUserDefaults] setObject:selfIds forKey:ck];
            mfLog(@"[iap] archive(self): %lu ids", (unsigned long)selfIds.count);
            cb(selfIds);
            return;
        }
        // AppForge fallback
        mfFetchArchiveIDsOnce(@"https://appforge-productid-api.tranthikimchi2601.workers.dev", trackId, YES, ^(NSArray *afIds) {
            if (afIds.count) [[NSUserDefaults standardUserDefaults] setObject:afIds forKey:ck];
            mfLog(@"[iap] archive(af): %lu ids", (unsigned long)afIds.count);
            cb(afIds);
        });
    });
}

// v2.6.13: 扫描结果回传自建库(众包闭环——装 MinisFix 的设备越多,库越全)
static void mfContributeToArchive(NSString *trackId, NSArray *verifiedPIDs) {
    if (!trackId.length || !verifiedPIDs.count) return;
    // 只回传 ≤200 条(防误传大列表),字段已在 SK 裁决时验证过
    NSArray *sub = verifiedPIDs.count > 200 ? [verifiedPIDs subarrayWithRange:NSMakeRange(0, 200)] : verifiedPIDs;
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    NSString *appName = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleDisplayName"]
        ?: [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleName"] ?: @"";
    NSMutableDictionary *payload = [NSMutableDictionary dictionaryWithObjectsAndKeys:
        trackId, @"trackId", bid, @"bundleId", appName, @"name", sub, @"productIds", nil];
    NSError *je = nil;
    NSData *body = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&je];
    if (!body) return;
    NSString *u = [NSString stringWithFormat:@"%@/v1/contribute", mfArchiveSelf];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:u]];
    req.HTTPMethod = @"POST";
    req.HTTPBody = body;
    req.timeoutInterval = 10;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [[NSURLSession.sharedSession dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            mfLog(@"[iap] contribute: %lu ids → http %@ e=%@", (unsigned long)sub.count, r, e.localizedDescription ?: @"-");
    }] resume];
}

// v2.6.11: App Store 产品页 IAP 商品名抓取——成功缓存到 UserDefaults,429 限流时用缓存兜底
static void mfFetchIAPTitles(NSString *trackId, void (^cb)(NSArray *titles)) {
    NSString *cacheKey = [NSString stringWithFormat:@"iapTitles_%@", trackId];
    NSArray *pre = [[NSUserDefaults standardUserDefaults] objectForKey:cacheKey];
    if (pre.count) { mfLog(@"[iap] guess: cache %lu titles", (unsigned long)pre.count); cb(pre); return; }
    NSString *pu = [NSString stringWithFormat:@"https://apps.apple.com/us/app/id%@", trackId];
            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:pu]];
            req.timeoutInterval = 10;
            [req setValue:@"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15" forHTTPHeaderField:@"User-Agent"];
            [req setValue:@"en-US,en;q=0.9" forHTTPHeaderField:@"Accept-Language"];
            [[NSURLSession.sharedSession dataTaskWithRequest:req
                completionHandler:^(NSData *d2, NSURLResponse *r2, NSError *e2) {
                    NSMutableArray *titles = [NSMutableArray array];
                    NSInteger code = [(NSHTTPURLResponse *)r2 statusCode];
                    if (d2.length > 1000 && code == 200) {
                        NSString *html = [[NSString alloc] initWithData:d2 encoding:NSUTF8StringEncoding];
                        NSRange ir = [html rangeOfString:@"In-App Purchases"];
                        if (ir.location != NSNotFound && ir.location + 12000 < html.length) {
                            NSString *seg = [html substringWithRange:
                                NSMakeRange(ir.location, MIN((NSUInteger)12000, html.length - ir.location))];
                            // v2.6.9: svelte 前端 li 与 span 间有 div 包裹——(?s) 跨行懒惰匹配到首个 span
                            NSRegularExpression *li = [NSRegularExpression
                                regularExpressionWithPattern:@"(?s)<li[^>]*>.*?<span[^>]*>(.*?)</span>" options:0 error:nil];
                            [li enumerateMatchesInString:seg options:0 range:NSMakeRange(0, seg.length)
                                usingBlock:^(NSTextCheckingResult *m2, NSMatchingFlags f, BOOL *s) {
                                    NSString *raw = [seg substringWithRange:[m2 rangeAtIndex:1]];
                                    if ([raw containsString:@"<"]) return; // SVG/标签噪音
                                    raw = [raw stringByReplacingOccurrencesOfString:@"&amp;" withString:@"&"];
                                    raw = [raw stringByReplacingOccurrencesOfString:@"&#183;" withString:@"·"];
                                    raw = [raw stringByReplacingOccurrencesOfString:@"&middot;" withString:@"·"];
                                    if (raw.length > 1) [titles addObject:raw];
                                }];
                        }
                    }
                    if (titles.count) {
                        [[NSUserDefaults standardUserDefaults] setObject:titles forKey:cacheKey];
                    } else if (code == 429) {
                        // v2.6.11: Apple 限流(retry-after 20s)——用缓存兜底
                        NSArray *cached = [[NSUserDefaults standardUserDefaults] objectForKey:cacheKey];
                        if (cached.count) {
                            mfLog(@"[iap] guess: 429 rate-limited, cache %lu titles", (unsigned long)cached.count);
                            cb(cached); return;
                        }
                    }
                    mfLog(@"[iap] guess: trackId=%@ titles=%lu http=%ld", trackId, (unsigned long)titles.count, (long)code);
                    cb(titles);
            }] resume];
}


// (静态挖 key 可能带拼接尾巴: RC SDK 有拼串习惯,如 com.xxxV5.81.0Q2U1.1.2Sspm_)
// v2.6.6: 从捕获的请求头提取 RC key——app 自己发的 Authorization 头,100% 准确
static void mfHarvestRCKeysFromCaptures(void) {
    if (!g_mfRCKeys) g_mfRCKeys = [NSMutableSet set];
    for (MFNetRecord *r in mfCapturedRecordsSnapshot()) {
        if (!r.reqHeaders) continue;
        NSString *auth = r.reqHeaders[@"Authorization"] ?: r.reqHeaders[@"authorization"];
        if (auth.length < 10) continue;
        NSRange rng = [auth rangeOfString:@"appl_"];
        if (rng.location == NSNotFound) continue;
        NSString *tail = [auth substringFromIndex:rng.location];
        NSRange end = [tail rangeOfCharacterFromSet:
            [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        NSString *cand = end.location == NSNotFound ? tail : [tail substringToIndex:end.location];
        if (mfIsRCPublicKey(cand)) [g_mfRCKeys addObject:cand];
        else {
            // appl_ 后紧跟引号等非 base62 字符时正则兜底
            NSError *e = nil;
            NSRegularExpression *rx = [NSRegularExpression
                regularExpressionWithPattern:@"appl_[A-Za-z0-9]{15,60}" options:0 error:&e];
            [rx enumerateMatchesInString:auth options:0 range:NSMakeRange(0, auth.length)
                usingBlock:^(NSTextCheckingResult *m, NSMatchingFlags f, BOOL *s) {
                    NSString *k = [auth substringWithRange:m.range];
                    if (mfIsRCPublicKey(k)) [g_mfRCKeys addObject:k];
                }];
        }
    }
}

static void mfQueryRevenueCatOfferings(NSString *key, void (^cb)(NSSet *pids)) {
    if (!key.length) { cb(nil); return; }
    // 一次性随机匿名 user id——RC 会自动创建空订阅者,不碰真实用户数据
    NSString *uid = [NSString stringWithFormat:@"mfprobe%08x%08x", arc4random(), arc4random()];
    NSString *urlStr = [NSString stringWithFormat:
        @"https://api.revenuecat.com/v1/subscribers/%@/offerings", uid];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
    req.HTTPMethod = @"GET";
    req.timeoutInterval = 10;
    [req setValue:[NSString stringWithFormat:@"Bearer %@", key] forHTTPHeaderField:@"Authorization"];
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"ios" forHTTPHeaderField:@"X-Platform"];
    [[NSURLSession.sharedSession dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSMutableSet *pids = [NSMutableSet set];
            if (d.length > 10) {
                NSString *body = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (body) {
                    NSError *er = nil;
                    NSRegularExpression *rx = [NSRegularExpression
                        regularExpressionWithPattern:@"\"platform_product_identifier\"\\s*:\\s*\"([^\"\\\\]{3,80})\""
                        options:0 error:&er];
                    [rx enumerateMatchesInString:body options:0 range:NSMakeRange(0, body.length)
                        usingBlock:^(NSTextCheckingResult *m, NSMatchingFlags f, BOOL *s) {
                            [pids addObject:[body substringWithRange:[m rangeAtIndex:1]]];
                        }];
                }
                mfLog(@"[iap] RC offerings key=%@ pids=%lu http=%@",
                      key, (unsigned long)pids.count, r);
            } else {
                mfLog(@"[iap] RC offerings fail key=%@: %@ http=%@",
                      key, e.localizedDescription ?: @"empty-body", r);
            }
            cb(pids);
    }] resume];
}

// SKProductsRequest 查询本地 PID 的价格
@interface MFProductReqDelegate : NSObject <SKProductsRequestDelegate>
@property (nonatomic, copy) void (^cb)(NSDictionary *prices, NSDictionary *titles);
@end
@implementation MFProductReqDelegate
- (void)productsRequest:(SKProductsRequest *)request didReceiveResponse:(SKProductsResponse *)response {
    NSMutableDictionary *map = [NSMutableDictionary dictionary];
    NSMutableDictionary *tmap = [NSMutableDictionary dictionary];
    for (SKProduct *p in response.products) {
        NSNumberFormatter *fmt = [[NSNumberFormatter alloc] init];
        fmt.numberStyle = NSNumberFormatterCurrencyStyle;
        fmt.locale = p.priceLocale;
        NSString *priceStr = [fmt stringFromNumber:p.price];
        if (priceStr.length) map[p.productIdentifier] = priceStr;
        // v2.6.15: localizedTitle 一并收集——面板展示商品名
        NSString *t = p.localizedTitle;
        if (t.length) tmap[p.productIdentifier] = t;
    }
    // v2.11.5: Apple 确认有效的商品 = 最高置信 → 文件级存储(mfFileIDsAdd) + Top + SavedIAPIDs
    extern void mfTopRecord(NSString *pid);
    extern void mfFileIDsAdd(NSString *pid);
    NSUserDefaults *dd = [NSUserDefaults standardUserDefaults];
    NSMutableArray *saved = [NSMutableArray arrayWithArray:([dd objectForKey:@"SavedIAPIDs"] ?: @[])];
    BOOL ch = NO;
    for (NSString *pid in map) {
        mfTopRecord(pid);
        mfFileIDsAdd(pid); // v2.11.8: app 抹 defaults 也抹不掉
        if (![saved containsObject:pid]) { [saved addObject:pid]; ch = YES; }
    }
    if (ch) { [dd setObject:saved forKey:@"SavedIAPIDs"]; [dd synchronize]; }
    if (map.count) mfLog(@"[iap] scan validated: %@ (saved %lu)", [map.allKeys componentsJoinedByString:@", "], (unsigned long)saved.count);
    if (self.cb) self.cb([map copy], [tmap copy]);
}
- (void)request:(SKRequest *)request didFailWithError:(NSError *)error {
    if (self.cb) self.cb(@{}, @{});
}
@end
static void mfQueryLocalPrices(NSArray *pids, void (^cb)(NSDictionary *pidToPrice, NSDictionary *pidToTitle)) {
    if (pids.count == 0) { cb(@{}, @{}); return; }
    SKProductsRequest *req = [[SKProductsRequest alloc] initWithProductIdentifiers:[NSSet setWithArray:pids]];
    MFProductReqDelegate *delegate = [[MFProductReqDelegate alloc] init];
    __block BOOL done = NO;
    delegate.cb = ^(NSDictionary *map, NSDictionary *tmap) {
        if (!done) { done = YES; cb(map, tmap); }
    };
    req.delegate = delegate;
    // 防 ARC 释放 delegate
    objc_setAssociatedObject(req, "delegate", delegate, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [req start];
    // 超时保护（8秒）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        if (!done) { done = YES; cb(@{}, @{}); }
    });
}

// v2.6.9: 分批验证——SKProductsRequest 单次大列表不可靠,500/批串行,聚合结果
static void mfQueryPricesBatched(NSArray *pids, NSMutableDictionary *acc, void (^cb)(NSDictionary *)) {
    if (!pids.count) { cb(acc); return; }
    NSUInteger n = MIN((NSUInteger)500, pids.count);
    NSArray *batch = [pids subarrayWithRange:NSMakeRange(0, n)];
    NSArray *rest = n < pids.count ? [pids subarrayWithRange:NSMakeRange(n, pids.count - n)] : @[];
    mfQueryLocalPrices(batch, ^(NSDictionary *map, NSDictionary *tmap) {
        [acc addEntriesFromDictionary:map];
        // v2.6.15: titles 聚合到关联对象——不改 cb 签名,调用端取
        NSMutableDictionary *tacc = objc_getAssociatedObject(acc, "titles");
        if (!tacc) { tacc = [NSMutableDictionary dictionary]; objc_setAssociatedObject(acc, "titles", tacc, OBJC_ASSOCIATION_RETAIN_NONATOMIC); }
        [tacc addEntriesFromDictionary:tmap];
        mfQueryPricesBatched(rest, acc, cb);
    });
}

// IAP 记录
static void mfProbeStoreKit2(void);  // v1.9.6 SK2 探针,定义在文件后部

static void IAPRecord(NSString *pid) {
    if (pid.length == 0) return;
    @autoreleasepool {
        // v2.11.1: 垃圾 ID 不入库(防 fake 反馈回路越滚越大)
        extern BOOL mfPIDLooksReal(NSString *pid);
        if (!mfPIDLooksReal(pid)) return;
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSMutableArray *list = [NSMutableArray arrayWithArray:([d objectForKey:@"SavedIAPIDs"] ?: @[])];
        if (![list containsObject:pid]) { [list addObject:pid]; [d setObject:list forKey:@"SavedIAPIDs"]; [d synchronize]; }
    }
}

// 解析价格字符串为数字（支持 ¥6.00, $0.99, €1,99, 0, 免费 等格式）
static double mfParsePrice(NSString *priceStr) {
    if (!priceStr.length || [priceStr isEqualToString:@"?"] || [priceStr isEqualToString:@"未上架"]) return 99999;
    if ([priceStr containsString:@"免费"] || [priceStr containsString:@"Free"]) return 0;
    // 提取数字部分（保留小数点，处理逗号作为小数点）
    NSMutableString *num = [NSMutableString string];
    BOOL hasDot = NO;
    for (NSUInteger i = 0; i < priceStr.length; i++) {
        unichar c = [priceStr characterAtIndex:i];
        if (c >= '0' && c <= '9') {
            [num appendFormat:@"%C", c];
        } else if ((c == '.' || c == ',') && !hasDot) {
            // 取最后一个数字分隔符作为小数点
            if (num.length > 0) {
                // 检查后面是否有数字
                BOOL digitAfter = NO;
                for (NSUInteger j = i + 1; j < priceStr.length; j++) {
                    unichar nc = [priceStr characterAtIndex:j];
                    if (nc >= '0' && nc <= '9') { digitAfter = YES; break; }
                    if (nc != ' ') break;
                }
                if (digitAfter) {
                    hasDot = YES;
                    [num appendString:@"."];
                }
            }
        }
    }
    return num.length > 0 ? [num doubleValue] : 99999;
}

// 扫描购买页（本地扫描 + SKProductsRequest 验证 + 在线查询，去重合并，按价格排序）
@interface MFScanList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *items; // {pid, title, price, src}
@end
@implementation MFScanList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return self.items.count; }
- (CGFloat)tableView:(UITableView *)tv heightForRowAtIndexPath:(NSIndexPath *)ip { return 66; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *idt = @"mfScanRow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:idt];
    if (!c) {
        c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:idt];
        c.backgroundColor = UIColor.clearColor;
        c.selectionStyle = UITableViewCellSelectionStyleDefault;
        UILabel *pid = [UILabel new]; pid.tag = 101;
        pid.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
        pid.textColor = [UIColor labelColor]; pid.lineBreakMode = NSLineBreakByTruncatingMiddle;
        UILabel *sub = [UILabel new]; sub.tag = 102;
        sub.font = [UIFont systemFontOfSize:11]; sub.textColor = [UIColor secondaryLabelColor];
        sub.lineBreakMode = NSLineBreakByTruncatingTail;
        UILabel *src = [UILabel new]; src.tag = 103;
        src.font = [UIFont systemFontOfSize:10]; src.textColor = [UIColor tertiaryLabelColor];
        src.lineBreakMode = NSLineBreakByTruncatingTail;
        [c.contentView addSubview:pid]; [c.contentView addSubview:sub]; [c.contentView addSubview:src];
    }
    NSDictionary *item = self.items[ip.row];
    CGFloat w = g_mfCardW - 32; // 新建 cell 时 contentView 未布局,用面板固定宽
    UILabel *pid = [c.contentView viewWithTag:101], *sub = [c.contentView viewWithTag:102], *src = [c.contentView viewWithTag:103];
    pid.frame = CGRectMake(16, 6, w, 18);   pid.text = item[@"pid"];
    sub.frame = CGRectMake(16, 25, w, 17);  sub.text = [item[@"title"] length] ?
        [NSString stringWithFormat:@"%@ · %@", item[@"title"], item[@"price"]] : item[@"price"];
    src.frame = CGRectMake(16, 43, w, 16);  src.text = [item[@"src"] length] ?
        [NSString stringWithFormat:@"来源: %@", item[@"src"]] : @"";
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    // 点按 = 购买(沿用 mfBuyProduct 语义)
    NSString *pid = self.items[ip.row][@"pid"];
    if (!pid.length) return;
    IAPRecord(pid);
    SKPayment *pay = [SKPayment paymentWithProductIdentifier:pid];
    [[SKPaymentQueue defaultQueue] addPayment:pay];
    mfLog(@"buy: %@", pid);
}
// 左划: 复制(蓝) / 购买(绿)——对标捕获列表
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSString *pid = self.items[ip.row][@"pid"];
    UIContextualAction *copy = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"复制" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [UIPasteboard generalPasteboard].string = pid;
            mfLog(@"copied: %@", pid);
            done(YES);
        }];
    copy.backgroundColor = [UIColor systemBlueColor];
    UIContextualAction *buy = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"购买" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            IAPRecord(pid);
            SKPayment *pay = [SKPayment paymentWithProductIdentifier:pid];
            [[SKPaymentQueue defaultQueue] addPayment:pay];
            mfLog(@"buy(swipe): %@", pid);
            done(YES);
        }];
    buy.backgroundColor = [UIColor systemGreenColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[copy, buy]];
}
@end

// v2.6.17: 宿主日志列表(对标 MFScanList) — Menlo 单列 + 左划复制, automatic 行高
@interface MFHostLogList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray<NSString *> *items;
@end
@implementation MFHostLogList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return self.items.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *idt = @"mfHlRow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:idt];
    if (!c) {
        c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:idt];
        c.backgroundColor = UIColor.clearColor;
        c.textLabel.font = [UIFont fontWithName:@"Menlo-Regular" size:10];
        c.textLabel.textColor = [UIColor labelColor];
        c.textLabel.lineBreakMode = NSLineBreakByCharWrapping;
        c.selectionStyle = UITableViewCellSelectionStyleNone;
    }
    c.textLabel.text = self.items[ip.row];
    return c;
}
- (CGFloat)tableView:(UITableView *)tv heightForRowAtIndexPath:(NSIndexPath *)ip {
    // 估算: Menlo 10pt 每行约 6px/字符, 宽度按面板估
    NSString *s = self.items[ip.row];
    CGFloat charsPerLine = MAX(20, (g_mfCardW - 32) / 6.0);
    CGFloat lines = ceil(MAX(1, s.length) / charsPerLine);
    return MAX(18, lines * 13 + 4);
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:NO];
}
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSString *line = self.items[ip.row];
    UIContextualAction *copy = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"复制" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [UIPasteboard generalPasteboard].string = line;
            done(YES);
        }];
    copy.backgroundColor = [UIColor systemBlueColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[copy]];
}
@end

void mfShowHostLogPage(void) {
    UIView *page = mfMakePage(@"实时日志", YES);

    // 控制条: 启停开关 + 状态 + 清空/复制全部
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, 40)];
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(12, 5, 51, 31)];
    sw.on = mfHostLogRunning();
    [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfHostLogSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    objc_setAssociatedObject(sw, "hlPage", page, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [bar addSubview:sw];

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(74, 11, g_mfCardW - 250, 20)];
    status.tag = 201;
    status.font = [UIFont systemFontOfSize:11];
    status.textColor = [UIColor secondaryLabelColor];
    status.text = mfHostLogRunning() ? @"捕获中" : @"已停止";
    [bar addSubview:status];

    UIButton *clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    clearBtn.frame = CGRectMake(g_mfCardW - 168, 5, 60, 31);
    [clearBtn setTitle:@"清空" forState:UIControlStateNormal];
    clearBtn.titleLabel.font = [UIFont systemFontOfSize:12];
    [clearBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfHostLogClearTapped:") forControlEvents:UIControlEventTouchUpInside];
    objc_setAssociatedObject(clearBtn, "hlPage", page, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [bar addSubview:clearBtn];

    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(g_mfCardW - 100, 5, 80, 31);
    [copyBtn setTitle:@"复制全部" forState:UIControlStateNormal];
    copyBtn.titleLabel.font = [UIFont systemFontOfSize:12];
    [copyBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfHostLogCopyAllTapped:") forControlEvents:UIControlEventTouchUpInside];
    objc_setAssociatedObject(copyBtn, "hlPage", page, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [bar addSubview:copyBtn];
    [page addSubview:bar];

    // 列表
    UITableView *tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 82, g_mfCardW, g_mfCardH - 82) style:UITableViewStylePlain];
    tv.tag = 210;
    tv.backgroundColor = [UIColor tertiarySystemBackgroundColor];
    tv.separatorStyle = UITableViewCellSeparatorStyleNone;
    MFHostLogList *list = [MFHostLogList new];
    list.items = mfHostLogSnapshot();
    tv.dataSource = list;
    tv.delegate = list;
    objc_setAssociatedObject(page, "hlList", list, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "hlLastCount", @(mfHostLogBufferedCount()), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    if (list.items.count) [tv scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:list.items.count-1 inSection:0] atScrollPosition:UITableViewScrollPositionBottom animated:NO];
    [page addSubview:tv];

    // 刷新: 0.5s 拉计数,变了才 reload; 页面 pop(superview==nil)自动停表
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC, 0.1 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        if (!page.superview) { dispatch_source_cancel(timer); return; }
        unsigned long long cnt = mfHostLogBufferedCount();
        unsigned long long last = [objc_getAssociatedObject(page, "hlLastCount") unsignedLongLongValue];
        if (cnt == last) return;
        objc_setAssociatedObject(page, "hlLastCount", @(cnt), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        UITableView *ltv = [page viewWithTag:210];
        MFHostLogList *ll = objc_getAssociatedObject(page, "hlList");
        if (!ltv || !ll) return;
        // 在底部才跟随滚动(用户上翻查历史不打扰)
        BOOL atBottom = ltv.contentOffset.y + ltv.bounds.size.height >= ltv.contentSize.height - 60;
        ll.items = mfHostLogSnapshot();
        [ltv reloadData];
        UILabel *st = [page viewWithTag:201];
        st.text = mfHostLogRunning()
            ? [NSString stringWithFormat:@"捕获中 · %llu 行", cnt]
            : [NSString stringWithFormat:@"已停止 · 缓冲 %llu 行", cnt];
        if (atBottom && ll.items.count)
            [ltv scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:ll.items.count-1 inSection:0] atScrollPosition:UITableViewScrollPositionBottom animated:NO];
    });
    dispatch_resume(timer);
    objc_setAssociatedObject(page, "hlTimer", timer, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    mfPushPage(page);
}

void mfShowScanPage(void) {
    UIView *page = mfMakePage(@"扫描购买", YES);
    // 启动即捕获开关(v2.0.0):下次启动生效——解决"App 先启动、后开捕获截不到老会话"

    // v2.58.7: 灰占位卡(不可点) — 全链路(指纹+产品SK verify)跑完才换成真侦查卡。
    //   用户定案: 产品ID先行(本地候选即时上屏), 侦查工作没跑完不给看详情(半吊子详情没意义)
    UIView *ph = [[UIView alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 32, 52)];
    ph.backgroundColor = [UIColor tertiarySystemFillColor];
    ph.layer.cornerRadius = 10;
    CGFloat phW = g_mfCardW - 32;
    UILabel *phT = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, phW - 24, 18)];
    phT.text = @"侦查: 正在分析二进制/框架/网络…";
    phT.font = [UIFont systemFontOfSize:12.5 weight:UIFontWeightSemibold];
    phT.textColor = [UIColor tertiaryLabelColor];
    [ph addSubview:phT];
    UILabel *phS = [[UILabel alloc] initWithFrame:CGRectMake(12, 28, phW - 24, 16)];
    phS.text = @"跑完自动替换为可点详情卡";
    phS.font = [UIFont systemFontOfSize:10.5];
    phS.textColor = [UIColor tertiaryLabelColor];
    [ph addSubview:phS];
    [page addSubview:ph];

    UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(16, 106, g_mfCardW - 32, 40)];
    st.text = @"正在扫描产品ID…";
    st.textAlignment = NSTextAlignmentCenter;
    st.font = [UIFont systemFontOfSize:14];
    st.textColor = [UIColor secondaryLabelColor];
    [page addSubview:st];
    mfPushPage(page);

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // v2.47.0: 内购模式一次性侦查(零 hook 纯读, 判据沉淀自 Reflix 战役终案) — 结果进置顶卡
        NSDictionary *recon = mfReconFingerprint();
        for (NSString *rl in recon[@"lines"]) mfLog(@"[recon] %@", rl);
        // 1.0 运行时截获回流(v2.6.11): SK1 hook 历史截获的 app 自查 ID——app 亲口报的,最高优先级
        // 依据: 任何 app 要展示/购买商品必发 SKProductsRequest(init 参数含全部 ID),打开一次购买页即现形
        NSArray *hookedPIDs = [[NSUserDefaults standardUserDefaults] objectForKey:@"SavedIAPIDs"] ?: @[];

        // 1. 本地扫描 + 网络提取（双源）
        NSArray *localCandidates = mfScanLocalProductIDs();
        NSArray *netPIDs = mfExtractPIDsFromCaptures();

        // 1.5 RevenueCat 路径(v2.6.4): 静态挖到的 appl_ key → offerings API 全量 productId
        // slug 形态 ID(live_level_subscription_monthly)静态扫描易漏,RC offerings 是开发者配置的完整列表
        NSArray *rcPIDs = @[];
        {
            mfHarvestRCKeysFromCaptures(); // v2.6.6: 请求头 key 优先——静态挖的可能带拼接尾巴
            NSSet *rcKeys = mfCollectedRCKeys();
            if (rcKeys.count) {
                dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                NSMutableSet *acc = [NSMutableSet set];
                for (NSString *k in rcKeys) {
                    mfQueryRevenueCatOfferings(k, ^(NSSet *pids) {
                        if (pids.count) [acc unionSet:pids];
                        dispatch_semaphore_signal(sem);
                    });
                }
                for (NSUInteger i = 0; i < rcKeys.count; i++)
                    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)));
                rcPIDs = acc.allObjects;
                mfLog(@"[iap] RC offerings: %lu pids / %lu keys", (unsigned long)rcPIDs.count, (unsigned long)rcKeys.count);
            }
        }

        // 1.6 App Store 情报(v2.6.12): lookup trackId → AppForge 档案库 IDs(众包库,最高命中) + 产品页 titles 猜测
        NSArray *guessPIDs = @[];
        NSArray *archivePIDs = @[];
        {
            NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
            if (bid.length) {
                dispatch_semaphore_t lsem = dispatch_semaphore_create(0);
                __block NSString *tid = nil;
                mfLookupTrackId(bid, ^(NSString *t) { tid = t; dispatch_semaphore_signal(lsem); });
                dispatch_semaphore_wait(lsem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)));
                if (tid.length) {
                    // 档案库查询(v2.6.12)
                    dispatch_semaphore_t asem = dispatch_semaphore_create(0);
                    __block NSArray *aids = nil;
                    mfFetchArchiveIDs(tid, ^(NSArray *ids) { aids = ids ?: @[]; dispatch_semaphore_signal(asem); });
                    dispatch_semaphore_wait(asem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)));
                    archivePIDs = aids;
                    // 产品页 titles → 猜测
                    dispatch_semaphore_t gsem = dispatch_semaphore_create(0);
                    __block NSArray *gtitles = nil;
                    mfFetchIAPTitles(tid, ^(NSArray *titles) {
                        gtitles = titles ?: @[];
                        dispatch_semaphore_signal(gsem);
                    });
                    dispatch_semaphore_wait(gsem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(12 * NSEC_PER_SEC)));
                    guessPIDs = mfGuessIDsFromTitles(gtitles);
                    mfLog(@"[iap] guess: %lu titles → %lu candidate ids", (unsigned long)gtitles.count, (unsigned long)guessPIDs.count);
                }
            }
        }

        // 1.7 片段组合(v2.6.8): 语义前缀 × 二进制片段——覆盖运行时拼接构造的 ID
        NSArray *comboPIDs = mfComboCandidates();
        mfLog(@"[iap] combo: %lu tokens → %lu candidates", (unsigned long)g_mfSlugTokens.count, (unsigned long)comboPIDs.count);

        mfLog(@"[iap] local=%d net=%lu rc=%lu guess=%lu combo=%lu → SK verify", (int)localCandidates.count, (unsigned long)netPIDs.count, (unsigned long)rcPIDs.count, (unsigned long)guessPIDs.count, (unsigned long)comboPIDs.count);
        dispatch_async(dispatch_get_main_queue(), ^{ mfProbeStoreKit2(); });

        NSMutableSet *seen = [NSMutableSet setWithArray:localCandidates];
        NSMutableArray *toVerify = [NSMutableArray arrayWithArray:hookedPIDs];   // 运行时截获最优先(v2.6.11)
        for (NSString *pid in archivePIDs) [toVerify addObject:pid];             // 档案库众包库次之(v2.6.12)
        for (NSString *pid in netPIDs) [toVerify addObject:pid];                 // 网络提取
        for (NSString *pid in rcPIDs) [toVerify addObject:pid];                  // RC offerings(v2.6.4)
        for (NSString *pid in guessPIDs) [toVerify addObject:pid];               // 商品名猜测(v2.6.7)
        // v2.47.5: protobuf/CoreML descriptor 字段名噪声过滤(AllPic 实测 470/471 候选是 byok_*/pro_* 编译器符号)
        NSMutableIndexSet *noiseIdx = [NSMutableIndexSet indexSet];
        [toVerify enumerateObjectsUsingBlock:^(NSString *pid, NSUInteger i, BOOL *stop) {
            NSString *lp = pid.lowercaseString;
            if ([lp hasPrefix:@"byok_"] || [lp hasPrefix:@"pro_allow"] ||
                [lp containsString:@"_package"] || [lp containsString:@"oneof_decl"] ||
                [lp containsString:@"source_code_info"] || [lp containsString:@"tensor_names"] ||
                [lp containsString:@"profiler_config"] || [lp containsString:@"_rhs_"] ||
                [lp containsString:@"_imatmul_"] || [lp containsString:@"serialization_dir"] ||
                [lp containsString:@"cache_writing_behavior"] || [lp containsString:@"use_async_create_calls"])
                [noiseIdx addIndex:i];
        }];
        if (noiseIdx.count) {
            mfLog(@"[iap] 噪声过滤: %lu 个 protobuf/CoreML 符号排除", (unsigned long)noiseIdx.count);
            [toVerify removeObjectsAtIndexes:noiseIdx];
        }
        for (NSString *pid in comboPIDs) [toVerify addObject:pid];               // 片段组合(v2.6.8)
        for (NSString *pid in localCandidates) [toVerify addObject:pid];
        NSString *bid2 = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
        NSArray *bseg = [bid2 componentsSeparatedByString:@"."];
        NSString *hostPref = bseg.count >= 2 ? [[NSString stringWithFormat:@"%@.%@", bseg[0], bseg[1]] lowercaseString] : @"";
        [toVerify sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
            BOOL ah = [a.lowercaseString hasPrefix:hostPref], bh = [b.lowercaseString hasPrefix:hostPref];
            return ah == bh ? NSOrderedSame : (ah ? NSOrderedAscending : NSOrderedDescending);
        }];
        if (toVerify.count > 1500) {
            mfLog(@"[iap] candidates %lu → capped 1500 (host-prefix first)", (unsigned long)toVerify.count);
            toVerify = [[toVerify subarrayWithRange:NSMakeRange(0, 1500)] mutableCopy];
        }

        // 2. SKProductsRequest 统一验证（Apple 裁判：有效才带价格回来）——v2.6.9 分批 500/批
        mfQueryPricesBatched(toVerify, [NSMutableDictionary dictionary], ^(NSDictionary *verifiedPrices) {
            mfLog(@"[iap] SK verified: %lu valid / %lu tried", (unsigned long)verifiedPrices.count, (unsigned long)toVerify.count);
            // v2.6.13: 验证通过的 ID 回传自建档案库(众包闭环)
            NSString *ctid = [[NSUserDefaults standardUserDefaults] stringForKey:
                [NSString stringWithFormat:@"trackId_%@", [[NSBundle mainBundle] bundleIdentifier] ?: @""]] ?: @"";
            mfContributeToArchive(ctid, verifiedPrices.allKeys);
            dispatch_async(dispatch_get_main_queue(), ^{
                [st removeFromSuperview];
                // v2.58.7: 全链路(SK verify 含)跑完 — 灰占位卡换真侦查卡(此刻详情才完整, 可点)
                if ([ph.superview isKindOfClass:[UIView class]]) {
                    [ph removeFromSuperview];
                    UIView *reconCard = mfReconMakeCard(recon);
                    objc_setAssociatedObject(page, "reconCard", reconCard, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                    [page addSubview:reconCard];
                }

                NSMutableArray *merged = [NSMutableArray array];
                NSSet *hookSet = [NSSet setWithArray:hookedPIDs];
                NSSet *archiveSet = [NSSet setWithArray:archivePIDs];
                NSSet *netSet = [NSSet setWithArray:netPIDs];
                NSSet *rcSet = [NSSet setWithArray:rcPIDs];
                NSSet *guessSet = [NSSet setWithArray:guessPIDs];
                NSSet *comboSet = [NSSet setWithArray:comboPIDs];
                NSSet *localSet = [NSSet setWithArray:localCandidates];
                NSMutableDictionary *titleMap = objc_getAssociatedObject(verifiedPrices, "titles");
                for (NSString *pid in verifiedPrices) {
                    // v2.6.16: 全部命中途径显示全称(一个 ID 可能被多条路径挖到)
                    NSMutableArray *srcs = [NSMutableArray array];
                    if ([hookSet containsObject:pid])    [srcs addObject:@"运行"];
                    if ([archiveSet containsObject:pid]) [srcs addObject:@"档案"];
                    if ([netSet containsObject:pid])     [srcs addObject:@"网络"];
                    if ([rcSet containsObject:pid])      [srcs addObject:@"RC"];
                    if ([guessSet containsObject:pid])   [srcs addObject:@"名字"];
                    if ([comboSet containsObject:pid])   [srcs addObject:@"片段组"];
                    if ([localSet containsObject:pid])   [srcs addObject:@"静态"];
                    [merged addObject:@{@"pid": pid, @"price": verifiedPrices[pid],
                        @"title": titleMap[pid] ?: @"", @"src": [srcs componentsJoinedByString:@" + "]}];
                }
                [merged sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                    double pa = mfParsePrice(a[@"price"]), pb = mfParsePrice(b[@"price"]);
                    return pa < pb ? NSOrderedAscending : (pa > pb ? NSOrderedDescending : NSOrderedSame);
                }];

                if (merged.count == 0) {
                    UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, g_mfCardH/2 - 40, g_mfCardW - 32, 90)];
                    e.numberOfLines = 0;
                    e.textAlignment = NSTextAlignmentCenter;
                    e.textColor = [UIColor secondaryLabelColor];
                    e.font = [UIFont systemFontOfSize:12];
                    e.text = [NSString stringWithFormat:@"未验证到有效的 IAP 产品（候选 %lu 全被 Apple 判无效）\n\n三条路任选其一后再来扫：\n① 进 App 升级/购买页逛一圈 → 重扫\n  （SK2 目录桥自动截，无需任何开关）\n② 在 App 里点一次真实购买再取消\n  （SK1 hook 日志现形）\n③ 仅当它从自家服务器拉配置时才需要：\n  网络分析开实时捕获 + 冷启动 + 逛页", (unsigned long)toVerify.count];
                    [page addSubview:e];
                    return;
                }

                // v2.58.7: 卡区(占位卡→真卡)y=46, 产品区 106 起 — 布局恒定
                UILabel *countLb = [[UILabel alloc] initWithFrame:CGRectMake(16, 106, g_mfCardW - 32, 20)];
                countLb.text = [NSString stringWithFormat:@"验证通过 %lu / 候选 %lu（左划复制 · 点按购买）",
                    (unsigned long)merged.count, (unsigned long)toVerify.count];
                countLb.font = [UIFont systemFontOfSize:11];
                countLb.textColor = [UIColor tertiaryLabelColor];
                [page addSubview:countLb];

                // v2.6.16: UITableView 三行 cell + 系统 swipe actions(对标捕获列表)
                UITableView *sv = [[UITableView alloc] initWithFrame:CGRectMake(0, 126, g_mfCardW, g_mfCardH - 126) style:UITableViewStylePlain];
                sv.backgroundColor = UIColor.clearColor;
                sv.separatorStyle = UITableViewCellSeparatorStyleNone;
                MFScanList *scanCtl = [MFScanList new];
                scanCtl.items = merged;
                sv.dataSource = scanCtl;
                sv.delegate = scanCtl;
                objc_setAssociatedObject(page, "scanCtl", scanCtl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                [page addSubview:sv];
                mfLog(@"scan done: verified=%lu total=%lu",
                    (unsigned long)verifiedPrices.count, (unsigned long)merged.count);
                // v2.47.5: 第三类判定回填 — 无云/mach 指纹时 SK 产品名就是形态答案(纯 StoreKit 本地型)
                if (merged.count > 0) {
                    NSString *topPid = merged[0][@"pid"];
                    BOOL isLife = [topPid.lowercaseString containsString:@"lifetime"] ||
                                  [topPid.lowercaseString containsString:@"forever"] ||
                                  [topPid.lowercaseString containsString:@"once"];
                    mfReconApplySKResult(recon, page, topPid, isLife);
                }
                });
        });
    });
}

// 手动购买页
void mfShowManualBuyPage(void) {
    UIView *page = mfMakePage(@"手动购买", YES);
    UITextField *tf = [[UITextField alloc] initWithFrame:CGRectMake(16, 56, g_mfCardW - 32, 42)];
    tf.borderStyle = UITextBorderStyleRoundedRect;
    tf.placeholder = @"输入产品 ID";
    tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tf.font = [UIFont systemFontOfSize:13];
    // Add Done toolbar to dismiss keyboard (avoids delegate issues on iOS 17 with iOS 26-built app)
    UIToolbar *toolbar = [[UIToolbar alloc] initWithFrame:CGRectMake(0, 0, g_mfCardW, 44)];
    toolbar.barStyle = UIBarStyleDefault;
    UIBarButtonItem *flex = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil];
    UIBarButtonItem *done = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:tf action:@selector(resignFirstResponder)];
    toolbar.items = @[flex, done];
    tf.inputAccessoryView = toolbar;
    [page addSubview:tf];
    objc_setAssociatedObject(page, "tf", tf, OBJC_ASSOCIATION_RETAIN);
    UIButton *buy = [UIButton buttonWithType:UIButtonTypeSystem];
    buy.frame = CGRectMake(16, 110, g_mfCardW - 32, 44);
    buy.backgroundColor = [UIColor systemBlueColor];
    buy.layer.cornerRadius = 12;
    [buy setTitle:@"购买" forState:UIControlStateNormal];
    [buy setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [buy addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDoManualBuy") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:buy];
    UILabel *res = [[UILabel alloc] initWithFrame:CGRectMake(16, 164, g_mfCardW - 32, 60)];
    res.numberOfLines = 0; res.font = [UIFont systemFontOfSize:13];
    res.textColor = [UIColor labelColor]; res.textAlignment = NSTextAlignmentCenter;
    [page addSubview:res];
    objc_setAssociatedObject(page, "res", res, OBJC_ASSOCIATION_RETAIN);
    mfPushPage(page);
}

// 图标解锁页
void mfShowIconPage(void) {
    UIView *page = mfMakePage(@"图标解锁", YES);
    NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
    NSDictionary *alt = info[@"CFBundleIcons"][@"CFBundleAlternateIcons"];
    NSArray *names = [alt allKeys];
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
    if (names.count == 0) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 60, g_mfCardW - 32, 40)];
        e.text = @"此 app 没有备用图标"; e.textAlignment = NSTextAlignmentCenter;
        e.textColor = [UIColor secondaryLabelColor]; [page addSubview:e];
    } else {
        CGFloat gw = (g_mfCardW - 32 - 12) / 2;
        CGFloat y = 8;
        for (NSUInteger i = 0; i < names.count; i++) {
            CGFloat x = (i % 2 == 0) ? 16 : 16 + gw + 12;
            if (i > 0 && i % 2 == 0) y += 62;
            UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
            b.frame = CGRectMake(x, y, gw, 56);
            b.backgroundColor = [UIColor secondarySystemBackgroundColor];
            b.layer.cornerRadius = 12;
            [b setTitle:names[i] forState:UIControlStateNormal];
            b.titleLabel.font = [UIFont systemFontOfSize:13];
            objc_setAssociatedObject(b, "icon", names[i], OBJC_ASSOCIATION_RETAIN);
            [b addTarget:g_mfCtrl action:NSSelectorFromString(@"mfIconTap:") forControlEvents:UIControlEventTouchUpInside];
            [sv addSubview:b];
        }
        sv.contentSize = CGSizeMake(g_mfCardW, y + 70);
        [page addSubview:sv];
    }
    mfPushPage(page);
}

// Product 子页
void mfShowProductPage(void) {
    UIView *page = mfMakePage(@"Product", YES);
    CGFloat gw = (g_mfCardW - 32 - 12) / 2;
    CGFloat gy = 48;
    gy = mfGridButton(page, 16, gy, gw, @"扫描购买", @"🔍", @selector(mfShowScanPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"手动购买", @"⌨️", @selector(mfShowManualBuyPage), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"图标解锁", @"🎨", @selector(mfShowIconPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"实验模拟", @"🧪", @selector(mfShowLabPage), NO, nil);
    mfPushPage(page);
}

// ====== 🧪 实验模拟 (v2.17.4) ======
// 【归属铁律】订阅注入/收据伪造这类实验功能统一挂本页, 删改实验功能时:
//   1. 只动本页内的开关行, 不动本页入口(Product 页「实验模拟」按钮)
//   2. 引擎文件(MFSubInject.m/MFReceiptForge.m)与 ctor 自启动一并保留
// v2.17.0 清理 SK1 通杀页时两个开关被连带删成死代码——教训: 实验功能必须有固定住址
extern long mfSubInjectHits(void);
extern BOOL mfSubInjectIsOn(void);
extern long mfReceiptForgeHits(void);
extern BOOL mfReceiptForgeIsOn(void);
extern BOOL mfL0IsOn(void);
extern long mfL0ObserverCount(void);
extern void mfL0SetOn(BOOL on);
extern BOOL mfExcIsOn(void);        // v2.54.0: EXCPROBE 应答器开关状态
extern long mfExcHits(void);        // 命中计数
extern void mfExcSetOn(BOOL on);    // 写状态


static UIView *mfSubSwitchRow(UIView *page, CGFloat y, NSString *title,
                              BOOL on, SEL action, NSString *status) {
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 52)];
    bar.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    bar.layer.cornerRadius = 10;
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(10, 10, 51, 31)];
    sw.on = on;
    [sw addTarget:g_mfCtrl action:action forControlEvents:UIControlEventValueChanged];
    [bar addSubview:sw];
    UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(72, 6, g_mfCardW - 96 - 10, 22)];
    l.text = title;
    l.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
    [bar addSubview:l];
    UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(72, 28, g_mfCardW - 96 - 10, 18)];
    st.text = status;
    st.font = [UIFont systemFontOfSize:11];
    st.textColor = [UIColor secondaryLabelColor];
    [bar addSubview:st];
    [page addSubview:bar];
    return bar;
}


void mfShowLabPage(void) {
    UIView *page = mfMakePage(@"🧪 实验模拟", YES);

    UIButton *scan = [UIButton buttonWithType:UIButtonTypeSystem];
    scan.frame = CGRectMake(16, 46, g_mfCardW - 32, 40);
    scan.backgroundColor = [UIColor systemGreenColor];
    scan.layer.cornerRadius = 9;
    [scan setTitle:@"🔍 去扫描购买（含侦查卡）" forState:UIControlStateNormal];
    [scan setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    scan.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [scan addTarget:g_mfCtrl action:@selector(mfShowScanPage) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:scan];

    // —— 订阅模拟组(Reven 同款机制, 2026-09-02 逆向回流) ——
    UILabel *grp = [[UILabel alloc] initWithFrame:CGRectMake(16, 94, g_mfCardW - 32, 20)];
    grp.text = @"订阅模拟";
    grp.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    grp.textColor = [UIColor secondaryLabelColor];
    [page addSubview:grp];

    // v2.50.0: 开关命名对齐侦查卡四态(绿卡云验证 / 蓝卡队列信任 / 蓝卡收据验证)
    mfSubSwitchRow(page, 124, @"云验证 mock（RevenueCat 系）", mfSubInjectIsOn(),
        @selector(mfSubInjectSwitchChanged:),
        [NSString stringWithFormat:@"对应侦查: 云验证 — RC/SW/Adapty 响应进程内伪造 · 命中 %ld", mfSubInjectHits()]);
    mfSubSwitchRow(page, 184, @"L0 队列伪造（队列信任型）", mfL0IsOn(),
        @selector(mfL0SwitchChanged:),
        [NSString stringWithFormat:@"对应侦查: 队列信任候选 — 点内购取消即翻转 · observers %ld", (long)mfL0ObserverCount()]);
    mfSubSwitchRow(page, 244, @"L1 收据伪造（收据验证型）", mfReceiptForgeIsOn(),
        @selector(mfReceiptForgeSwitchChanged:),
        [NSString stringWithFormat:@"对应侦查: 收据验证型 — appStoreReceiptURL/transactionReceipt · 命中 %ld", mfReceiptForgeHits()]);

    // v2.56.3: 删除"mach 许可服务器应答器（demux 重绑）"开关 —— 三连失败已证伪
    //   (fishhook rebind 0×3, 样本 dlsym 动态解析 mach_msg_server; demux 是样本自身代码,
    //    且授权判定链 = keychain+cloudkit); mfMachRespHits 还误用了 g_excHitCount(虚报)。
    

    // v2.56: patch 引擎(规则驱动: method swizzle / text vm_protect / keychain 授权豁免)
    //   ——学习自 ScriptingPass 判定链的落地容器。规则格式: mfAppPatchRules JSON
    //   [{"bid":"com.scripting.ios","ver":"","patches":[{"kind":"keychain"}]}]
    CGFloat apY = 304;   // v2.57.1: L1 行(296 结束)+8 — 原mach应答器删除留下的 72px 死区收回
    extern void mfAppPatchSectionInLabPage(UIView *page, CGFloat *yio);
    mfAppPatchSectionInLabPage(page, &apY);

    mfPushPage(page);
}

// ====== MFPanelCtrl（所有 action 方法） ======
// v2.6.16: 扫描结果列表(UITableView)——三行 cell(pid/商品名·价格/来源) + 系统 swipe actions
@interface MFPanelCtrl : NSObject @end
@implementation MFPanelCtrl
- (void)mfPopPage { mfPopPage(); }
- (void)mfClosePanel { mfClosePanel(); }


// 页面入口
- (void)mfShowDataAnalysisPage { mfShowDataAnalysisPage(); }
- (void)mfShowLabPage { mfShowLabPage(); } // v2.17.4 实验模拟: 订阅注入/收据伪造固定住址
// v2.6.17 实时日志
- (void)mfShowHostLogPage { mfShowHostLogPage(); }
// v2.6.21 电池详情
- (void)mfShowBatteryPage { mfShowBatteryPage(); }
- (void)mfHostLogSwitchChanged:(UISwitch *)sw {
    mfSetBoolPref(@"mfHostLogEnabled", sw.on);
    if (sw.on) mfHostLogStart();
    else mfHostLogStop();
    // 状态栏即时刷新(不等 0.5s timer)
    UIView *page = objc_getAssociatedObject(sw, "hlPage");
    UILabel *st = [page viewWithTag:201];
    if (st) st.text = sw.on ? @"捕获中" : @"已停止";
}
- (void)mfHostLogClearTapped:(UIButton *)btn {
    mfHostLogClear();
    UIView *page = objc_getAssociatedObject(btn, "hlPage");
    UITableView *tv = [page viewWithTag:210];
    MFHostLogList *ll = objc_getAssociatedObject(page, "hlList");
    ll.items = @[];
    objc_setAssociatedObject(page, "hlLastCount", @(mfHostLogBufferedCount()), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [tv reloadData];
    mfToast(@"已清空");
}
- (void)mfHostLogCopyAllTapped:(UIButton *)btn {
    NSArray *lines = mfHostLogSnapshot();
    [UIPasteboard generalPasteboard].string = [lines componentsJoinedByString:@"\n"];
    mfToast([NSString stringWithFormat:@"已复制 %lu 行", (unsigned long)lines.count]);
}
- (void)mfShowNetworkCapturePage { mfShowNetworkCapturePage(); }
- (void)mfShowCryptoPage { mfShowCryptoToolboxPage(); }
- (void)mfShowNetworkModifyPage { mfShowNetworkModifyPage(); }
- (void)mfShowFlexPage { }  // FLEX 已砍——保留空方法防止 KVO/archive 崩
- (void)mfShowProductPage { mfShowProductPage(); }
- (void)mfShowScanPage { mfShowScanPage(); }
- (void)mfShowKeychainManagerPage { mfShowKeychainManagerPage(); }
- (void)mfShowKeychainListPage { mfShowKeychainListPageAction(); }
- (void)mfCopyKeychainAction { mfCopyKeychainAction(); }
- (void)mfShowRestorePromptAction { mfShowRestorePromptAction(); }
- (void)mfFetchCloudKitRecordIDAuto { mfFetchCloudKitRecordIDAuto(); }
// 诊断（MFDiagnostics.m）
- (void)mfShowMachODeepPage { mfShowMachODeepPage(); }
- (void)mfShowNetAnalyzerPage { mfShowNetAnalyzerPage(); }
- (void)mfShowRuleManagerPage { mfShowRuleManagerPage(); }
// T1 解密捕获 / 方法监控
- (void)mfShowCryptoCapturePage { mfShowCryptoCapturePage(); }
- (void)mfCryptoSwitchChanged:(UISwitch *)sw { mfCryptoCapSwitchChanged(sw); }
- (void)mfCryptoClearTapped { mfCryptoClearTapped(); }
- (void)mfShowMethodTracePage { mfShowObjCHookPage(); }
- (void)mfShowCDHistoryPage { mfShowCDHistoryPage(); }
- (void)mfObjCHookFormAddTapped { mfObjCHookFormAddTapped(); }
- (void)mfObjCLocatorTapped { mfShowSelectorLocatorPage(); }
- (void)mfDefaultsBrowserTapped { mfShowDefaultsBrowserPage(); }
- (void)mfObjCLocateScan:(UIButton *)b { mfRunSelectorLocatorFromButton(b); }
- (void)mfObjCForceSandboxTapped { mfObjCForceSandboxTapped(); }
- (void)mfObjCTxProbeTapped { mfObjCTxProbeTapped(); }
- (void)mfSubInjectSwitchChanged:(UISwitch *)sw { mfSubInjectSwitchChanged(sw); }
- (void)mfReceiptForgeSwitchChanged:(UISwitch *)sw { mfReceiptForgeSwitchChanged(sw); }
- (void)mfL0SwitchChanged:(UISwitch *)sw { mfL0SetOn(sw.on); }
- (void)mfExcSwitchChanged:(UISwitch *)sw { mfExcSetOn(sw.on); }   // v2.54.0: EXCPROBE 应答器开关
- (void)mfObjCHookToggle:(UISwitch *)sw { mfObjCHookToggle(sw); }
- (void)mfObjCHookDelTapped:(UIButton *)b { mfObjCHookDelTapped(b); }
- (void)mfObjCHookEditTapped:(UIView *)row { mfObjCHookEditTappedFromView(row); }
- (void)mfObjCHookSwipeDel:(UIView *)row { mfObjCHookSwipeDelFromView(row); }
- (void)mfMachORun:(UIButton *)btn {
    btn.enabled = NO;
    NSString *kind = objc_getAssociatedObject(btn, "kind");
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = nil, *title = nil;
        if ([kind isEqualToString:@"sec"]) { report = mfMachOSections(); title = @"Sections 全览"; }
        else if ([kind isEqualToString:@"dylib"]) { report = mfMachODylibs(); title = @"Dylib 依赖"; }
        else if ([kind isEqualToString:@"str"]) { report = mfMachOStrings(); title = @"__cstring 抽样"; }
        else if ([kind isEqualToString:@"sym"]) { report = mfMachOSymbols(); title = @"符号表概览"; }
        else if ([kind isEqualToString:@"rt"]) { report = mfMachORuntime(); title = @"ObjC 运行时归属"; }
        dispatch_async(dispatch_get_main_queue(), ^{
            btn.enabled = YES;
            if (!report) return;
            mfShowTextReportPage(title, report, @"MachODeep");
        });
    });
}
- (void)mfDiagCopy:(UIButton *)btn {
    UIView *page = objc_getAssociatedObject(btn, "page");
    NSString *text = objc_getAssociatedObject(page, "text");
    if (text.length) [UIPasteboard generalPasteboard].string = text;
}
- (void)mfDiagShare:(UIButton *)btn {
    UIView *page = objc_getAssociatedObject(btn, "page");
    NSString *text = objc_getAssociatedObject(page, "text");
    NSString *name = objc_getAssociatedObject(page, "name") ?: @"report";
    if (!text.length) return;
    NSString *tmpDir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"mfdiag_share"];
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.dateFormat = @"yyyyMMdd_HHmmss";
    NSString *tmpFile = [tmpDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_%@.txt", name,
        [df stringFromDate:[NSDate date]] ?: @"report"]];
    [text writeToFile:tmpFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
    UIView *overlay = g_mfPanelOverlay;
    overlay.hidden = YES; // 面板遮罩会盖住 presentation
    UIActivityViewController *av = [[UIActivityViewController alloc]
            initWithActivityItems:@[[NSURL fileURLWithPath:tmpFile]] applicationActivities:nil];
    av.completionWithItemsHandler = ^(UIActivityType type, BOOL completed, NSArray *items, NSError *error) {
        overlay.hidden = NO;
        [[NSFileManager defaultManager] removeItemAtPath:tmpDir error:nil];
    };
    UIViewController *presenter = g_mfPanelRootVC;
    while (presenter.presentedViewController && presenter.presentedViewController != presenter)
        presenter = presenter.presentedViewController;
    if (!presenter || !presenter.view.window)
        for (UIWindow *w in [UIApplication sharedApplication].windows)
            if (w.isKeyWindow) { presenter = w.rootViewController; break; }
    if (presenter && presenter.view.window) [presenter presentViewController:av animated:YES completion:nil];
    else overlay.hidden = NO;
}

// ClassDump（数据分析板块）
- (void)mfShowClassDumpPage { mfShowClassDumpPage(); }
- (void)mfClassDumpStart:(UIButton *)btn {
    NSArray *trio = objc_getAssociatedObject(btn, "trio");
    if (!trio || trio.count < 3) return;
    btn.enabled = NO;
    mfClassDumpStartAction(trio[0], trio[1], btn, trio[2]);
}
// 浏览头文件：列表页（zip 按需解压，不落双份盘）
- (void)mfCDBrowserOpen:(UIButton *)btn {
    NSString *path = objc_getAssociatedObject(btn, "path");
    if (!path || ![[NSFileManager defaultManager] fileExistsAtPath:path]) return;
    mfShowCDBrowserPage(path);
}
// 详情页复制全文（viewer 从 sender associated 取）
- (void)mfCDFileCopy:(UIButton *)btn {
    id viewer = objc_getAssociatedObject(btn, "viewer");
    NSString *content = [viewer valueForKey:@"content"];
    if (content.length) [UIPasteboard generalPasteboard].string = content;
}
// 详情页分享单文件（解压到临时目录 → 分享面板 → 清理）
- (void)mfCDFileShare:(UIButton *)btn {
    id viewer = objc_getAssociatedObject(btn, "viewer");
    NSString *zipPath = [viewer valueForKey:@"zipPath"];
    NSString *entryName = [viewer valueForKey:@"entryName"];
    NSDictionary *idx = mfZipBuildIndex(zipPath);
    NSValue *v = idx[entryName];
    if (!v) return;
    MFZipEnt e; [v getValue:&e];
    NSData *data = mfZipReadEntry(zipPath, &e);
    if (!data) return;
    NSString *tmpDir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"mfcd_share"];
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *tmpFile = [tmpDir stringByAppendingPathComponent:entryName.lastPathComponent];
    [data writeToFile:tmpFile atomically:YES];
    UIView *overlay = g_mfPanelOverlay;
    overlay.hidden = YES; // 面板遮罩会盖住 presentation
    UIActivityViewController *av = [[UIActivityViewController alloc]
            initWithActivityItems:@[[NSURL fileURLWithPath:tmpFile]] applicationActivities:nil];
    av.completionWithItemsHandler = ^(UIActivityType type, BOOL completed, NSArray *items, NSError *error) {
        overlay.hidden = NO;
        [[NSFileManager defaultManager] removeItemAtPath:tmpDir error:nil];
    };
    UIViewController *presenter = g_mfPanelRootVC;
    while (presenter.presentedViewController && presenter.presentedViewController != presenter)
        presenter = presenter.presentedViewController;
    if (!presenter || !presenter.view.window)
        for (UIWindow *w in [UIApplication sharedApplication].windows)
            if (w.isKeyWindow) { presenter = w.rootViewController; break; }
    if (presenter && presenter.view.window) [presenter presentViewController:av animated:YES completion:nil];
    else overlay.hidden = NO;
}
- (UIViewController *)mfCDTopPresenter {
    UIViewController *presenter = g_mfPanelRootVC;
    while (presenter.presentedViewController && presenter.presentedViewController != presenter)
        presenter = presenter.presentedViewController;
    return presenter;
}
// 导出：分享面板自带"存储到文件"。关键：面板遮罩是手动 addSubview 到 keyWindow 的，
// 会盖住 VC presentation 层级——展示期间临时隐藏遮罩，结束后恢复
- (void)mfClassDumpExport:(UIButton *)btn {
    NSString *path = objc_getAssociatedObject(btn, "path");
    if (!path || ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        mfLog(@"CLASSDUMP export: path invalid %@", path);
        return;
    }
    UIView *overlay = g_mfPanelOverlay;
    UIActivityViewController *av = [[UIActivityViewController alloc]
            initWithActivityItems:@[[NSURL fileURLWithPath:path]] applicationActivities:nil];
    av.completionWithItemsHandler = ^(UIActivityType type, BOOL completed, NSArray *items, NSError *error) {
        overlay.hidden = NO; // 恢复面板
    };
    overlay.hidden = YES;
    UIViewController *presenter = [self mfCDTopPresenter];
    if (!presenter || !presenter.view.window) presenter = mfTopVC();   // v2.7.2: 兜底统一
    if (presenter && presenter.view.window) {
        [presenter presentViewController:av animated:YES completion:nil];
    } else {
        overlay.hidden = NO; // 实在没地方展示，恢复面板别把用户晾着
        mfLog(@"CLASSDUMP export: no presenter available");
    }
}
- (void)mfShowManualBuyPage { mfShowManualBuyPage(); }
- (void)mfShowIconPage { mfShowIconPage(); }

// Keychain 详情
- (void)mfShowKeychainDetail:(UIButton *)btn {
    NSDictionary *item = objc_getAssociatedObject(btn, "item");
    if (!item) return;
    mfShowKeychainDetail(item);
}

// Keychain 删除
- (void)mfDeleteKeychainItem:(UIButton *)btn {
    NSDictionary *item = objc_getAssociatedObject(btn, "item");
    if (!item) return;
    mfDeleteKeychainItem(btn);
}

// Keychain Dump（主页按钮）
- (void)mfDumpCurrentApp { mfDumpCurrentAppKeychain(); }

// Keychain 详情页：模式切换
- (void)mfKeychainDataDisplay:(UIButton *)btn { mfKeychainDataDisplayFromButton(btn); }

// Keychain 详情页：复制数据
- (void)mfCopyKeychainData:(UIButton *)btn { mfCopyKeychainDataFromDetailButton(btn); }

// Keychain 详情页：编辑/保存
- (void)mfEditKeychainData:(UIButton *)btn { mfEditKeychainDataFromDetailButton(btn); }

// Keychain Dump 页：复制 JSON
- (void)mfCopyDumpJson:(UIButton *)btn { mfCopyDumpJsonFromButton(btn); }

// Keychain 恢复页：执行恢复
- (void)mfDoRestoreFromPage:(UIButton *)btn { mfDoRestoreFromPageButton(btn); }

// 键盘附件工具条
- (void)mfKbSaveAndDismiss:(UIBarButtonItem *)item { mfKbSaveAndDismissFromBar(item); }
- (void)mfKbDismissKeyboard:(UIBarButtonItem *)item { mfKbDismissKeyboardFromBar(item); }

// iCloud Record ID 复制 (从列表页点击 cell)
- (void)mfCopyICloudRecordID:(UITapGestureRecognizer *)tap {
    UIView *cell = tap.view;
    if (!cell) return;
    mfCopyICloudRecordIDFromCell(self, cell);
}

// 捕获详情
- (void)mfShowCaptureDetail:(UITapGestureRecognizer *)g {
    MFNetRecord *rec = objc_getAssociatedObject(g, "rec");
    mfShowCaptureDetailPage(rec);
}
- (void)mfCopyRecord:(UIButton *)btn {
    MFNetRecord *rec = objc_getAssociatedObject(btn, "rec");
    if (!rec) return;
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"%@ %ld %@\n", rec.method ?: @"?", (long)rec.status, rec.url ?: @"?"];
    [s appendString:@"\n--- 请求 Headers ---\n"];
    for (NSString *k in rec.reqHeaders) [s appendFormat:@"%@: %@\n", k, rec.reqHeaders[k]];
    if (rec.reqBody.length) {
        [s appendString:@"\n--- 请求 Body ---\n"];
        [s appendString:[[NSString alloc] initWithData:rec.reqBody encoding:NSUTF8StringEncoding] ?: @""];
    }
    [s appendString:@"\n--- 响应 Headers ---\n"];
    for (NSString *k in rec.respHeaders) [s appendFormat:@"%@: %@\n", k, rec.respHeaders[k]];
    if (rec.respBody.length) {
        [s appendString:@"\n--- 响应 Body ---\n"];
        [s appendString:[[NSString alloc] initWithData:rec.respBody encoding:NSUTF8StringEncoding] ?: @""];
    }
    [UIPasteboard generalPasteboard].string = s;
    mfLog(@"copied %lu chars to pasteboard", (unsigned long)s.length);
    // 视觉反馈
    [UIView animateWithDuration:0.15 animations:^{ btn.alpha = 0.3; } completion:^(BOOL f){ btn.alpha = 1; }];
}

// 详情页"改响应"→ 用当前记录 URL 预填规则编辑页
- (void)mfModifyResponse:(UIButton *)btn {
    MFNetRecord *rec = objc_getAssociatedObject(btn, "rec");
    if (!rec) return;
    // 预填：scheme://host（包含匹配该域名所有请求）
    NSString *pattern = rec.url ?: @"";
    NSURL *u = [NSURL URLWithString:pattern];
    if (u.host.length > 0) {
        pattern = [NSString stringWithFormat:@"%@://%@", u.scheme ?: @"https", u.host];
    }
    mfShowRuleEditPage(pattern, @"replaceResp", -1, NO);
}

// 网格开关
- (void)mfGridSwitchChanged:(UIButton *)b {
    NSString *key = objc_getAssociatedObject(b, "pfx");
    if (!key) return;
    BOOL on = !mfPrefBool(key, NO);
    mfSetBoolPref(key, on);
    b.backgroundColor = on ? [UIColor systemGreenColor] : [UIColor secondarySystemBackgroundColor];
    mfLog(@"switch %@ -> %d", key, on);
}

// 网络捕获开关（v2.0.1 持久化：默认开，手动关过则冷启动也不自动开）
// v2.56.3: per-app —— key 改为 mfCaptureEnabled_<bid>(不同 app 独立; 修复跨 app 共享)
- (void)mfCaptureSwitchChanged:(UISwitch *)sw {
    g_captureEnabled = sw.on;
    mfSetBoolPref([NSString stringWithFormat:@"mfCaptureEnabled_%@", [[NSBundle mainBundle] bundleIdentifier]], sw.on);
    if (sw.on) {
        extern void mfInstallNetworkCapture(void);
        mfInstallNetworkCapture();
        mfLog(@"capture ON — NSURLProtocol registered");
    }
    mfLog(@"capture -> %d", sw.on);
}

// 拦截修改开关
- (void)mfRewriteSwitchChanged:(UISwitch *)sw {
    g_rewriteEnabled = sw.on;
    mfLog(@"rewrite -> %d", sw.on);
}

// 规则行开关
- (void)mfRuleSwitchChanged:(UISwitch *)sw {
    NSInteger idx = [objc_getAssociatedObject(sw, "idx") integerValue];
    if (idx >= 0 && idx < (NSInteger)g_rewriteRules.count) {
        ((MFRewriteRule *)g_rewriteRules[idx]).enabled = sw.on;
        mfSaveRule(g_rewriteRules[idx], idx);
        mfLog(@"rule %ld enabled -> %d", (long)idx, sw.on);
    }
}

// 编辑规则
- (void)mfEditRuleTapped:(UIButton *)btn {
    NSInteger idx = [objc_getAssociatedObject(btn, "idx") integerValue];
    if (idx >= 0 && idx < (NSInteger)g_rewriteRules.count) {
        mfShowRuleEditPage(nil, nil, idx, YES);
    }
}

// 删除规则（带确认）
- (void)mfDeleteRuleTapped:(UIButton *)btn {
    NSInteger idx = [objc_getAssociatedObject(btn, "idx") integerValue];
    if (idx < 0 || idx >= (NSInteger)g_rewriteRules.count) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"删除规则"
        message:[NSString stringWithFormat:@"确定删除这条规则？\n%@", ((MFRewriteRule *)g_rewriteRules[idx]).pattern]
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"删除" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        mfRemoveRule(idx);
        mfPopPage(); mfShowNetworkModifyPage();
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    UIViewController *vc = g_mfPanelRootVC;
    if (vc) [vc presentViewController:alert animated:YES completion:nil];
}

// 保存规则（旧版编辑页，兼容保留）
- (void)mfSaveRuleTapped:(UIButton *)btn {
    UISegmentedControl *matchSeg = objc_getAssociatedObject(btn, "seg");
    UISegmentedControl *actSeg = objc_getAssociatedObject(btn, "seg2");
    UITextField *patField = objc_getAssociatedObject(btn, "f1");
    UITextField *urlField = objc_getAssociatedObject(btn, "f2");
    UITextView *bodyView = objc_getAssociatedObject(btn, "tv");
    NSInteger index = [objc_getAssociatedObject(btn, "idx") integerValue];
    BOOL fromList = [objc_getAssociatedObject(btn, "fromList") boolValue];

    NSString *pattern = [patField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (pattern.length == 0) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示" message:@"请填写匹配的 URL" preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [g_mfPanelRootVC presentViewController:alert animated:YES completion:nil];
        return;
    }
    NSString *matchType = matchSeg.selectedSegmentIndex == 1 ? @"url" : (matchSeg.selectedSegmentIndex == 2 ? @"regex" : @"contain");
    NSString *action = actSeg.selectedSegmentIndex == 1 ? @"replaceReq" : (actSeg.selectedSegmentIndex == 2 ? @"block" : @"replaceResp");

    MFRewriteRule *r = [MFRewriteRule new];
    r.pattern = pattern;
    r.matchType = matchType;
    r.action = action;
    r.urlReplace = urlField.text ?: @"";
    r.bodyReplace = bodyView.text ?: @"";
    r.headerReplaces = @{};
    r.enabled = YES;
    if (index >= 0 && index < (NSInteger)g_rewriteRules.count) {
        r.appBundle = ((MFRewriteRule *)g_rewriteRules[index]).appBundle;
    } else {
        r.appBundle = mfCurrentBundleId();
    }
    mfSaveRule(r, index);
    mfPopPage();
    if (fromList) { mfPopPage(); mfShowNetworkModifyPage(); }
}

// 保存规则（新版增强编辑页：四象限 + direction + reject）
- (void)mfSaveRuleFromEditor:(UIButton *)btn {
    UISegmentedControl *matchSeg = objc_getAssociatedObject(btn, "seg");
    UISegmentedControl *dirSeg = objc_getAssociatedObject(btn, "seg2");
    UISwitch *rejectSw = objc_getAssociatedObject(btn, "rsw");
    UITextField *patField = objc_getAssociatedObject(btn, "f1");
    UITextField *nameField = objc_getAssociatedObject(btn, "f2");
    UITextView *reqHView = objc_getAssociatedObject(btn, "tv1");
    UITextView *respHView = objc_getAssociatedObject(btn, "tv2");
    UITextView *reqBView = objc_getAssociatedObject(btn, "tv3");
    UITextView *respBView = objc_getAssociatedObject(btn, "tv4");
    NSInteger index = [objc_getAssociatedObject(btn, "idx") integerValue];
    BOOL fromList = [objc_getAssociatedObject(btn, "fromList") boolValue];

    NSString *pattern = [patField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (pattern.length == 0) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示" message:@"请填写匹配的 URL" preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [g_mfPanelRootVC presentViewController:alert animated:YES completion:nil];
        return;
    }
    NSString *matchType = matchSeg.selectedSegmentIndex == 1 ? @"url" : (matchSeg.selectedSegmentIndex == 2 ? @"regex" : @"contain");
    NSString *direction = dirSeg.selectedSegmentIndex == 1 ? @"request" : (dirSeg.selectedSegmentIndex == 2 ? @"response" : @"");
    BOOL reject = rejectSw.on;

    // 解析 JSON Headers（失败回退空字典）
    NSDictionary *reqH = @{}, *respH = @{};
    @try { reqH = [NSJSONSerialization JSONObjectWithData:[reqHView.text dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil]; } @catch (...) {}
    @try { respH = [NSJSONSerialization JSONObjectWithData:[respHView.text dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil]; } @catch (...) {}

    MFRewriteRule *r = [MFRewriteRule new];
    r.pattern = pattern;
    r.matchType = matchType;
    r.action = reject ? @"block" : @"replaceResp";  // legacy 兼容
    r.urlReplace = @"";
    r.bodyReplace = respBView.text ?: @"";
    r.headerReplaces = @{};
    r.enabled = YES;
    r.direction = direction;
    r.reject = reject;
    r.name = nameField.text ?: @"";
    r.reqHeaders = reqH;
    r.respHeaders = respH;
    r.reqBody = reqBView.text ?: @"";
    r.respBody = respBView.text ?: @"";
    if (index >= 0 && index < (NSInteger)g_rewriteRules.count) {
        r.appBundle = ((MFRewriteRule *)g_rewriteRules[index]).appBundle;
    } else {
        r.appBundle = mfCurrentBundleId();
    }
    mfSaveRule(r, index);
    mfPopPage();
    if (fromList) { mfPopPage(); mfShowNetworkModifyPage(); }
}

// 添加规则（列表页）——走增强编辑页
- (void)mfAddRuleTapped {
    mfShowRuleEditPage(nil, @"replaceResp", -1, YES);
}



// IAP 购买
- (void)mfBuyProduct:(UIButton *)b {
    NSString *pid = objc_getAssociatedObject(b, "pid");
    if (!pid) return;
    IAPRecord(pid);
    SKPayment *pay = [SKPayment paymentWithProductIdentifier:pid];
    [[SKPaymentQueue defaultQueue] addPayment:pay];
    b.backgroundColor = [UIColor systemGreenColor];
    mfLog(@"buy: %@", pid);
}

// v2.6.10: 左划复制 productId——swipe 手势挂在结果行上,闪绿反馈
- (void)mfCopyRowSwipe:(UISwipeGestureRecognizer *)g {
    UIButton *row = (UIButton *)g.view;
    NSString *pid = objc_getAssociatedObject(row, "pid");
    if (!pid.length) return;
    [UIPasteboard generalPasteboard].string = pid;
    UIColor *orig = row.backgroundColor;
    row.backgroundColor = [UIColor systemGreenColor];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.9 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        row.backgroundColor = orig;
    });
    mfLog(@"copied: %@", pid);
}
- (void)mfDoManualBuy {
    UIView *top = [g_mfPages lastObject];
    UITextField *tf = objc_getAssociatedObject(top, "tf");
    UILabel *res = objc_getAssociatedObject(top, "res");
    NSString *pid = [[tf text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (pid.length == 0) { res.text = @"请输入产品 ID"; return; }
    IAPRecord(pid);
    SKPayment *pay = [SKPayment paymentWithProductIdentifier:pid];
    [[SKPaymentQueue defaultQueue] addPayment:pay];
    res.text = [NSString stringWithFormat:@"已发起购买:\n%@", pid];
    res.textColor = [UIColor systemGreenColor];
    mfLog(@"manual buy: %@", pid);
}
- (void)mfIconTap:(UIButton *)b {
    NSString *nm = objc_getAssociatedObject(b, "icon");
    if (!nm) return;
    UIApplication *app = [UIApplication sharedApplication];
    if ([app respondsToSelector:@selector(setAlternateIconName:completionHandler:)]) {
        [app setAlternateIconName:nm completionHandler:^(NSError *e) {
            mfLog(@"icon %@ -> %@", nm, e ? e.localizedDescription : @"ok");
        }];
        b.backgroundColor = [UIColor systemGreenColor];
    }
}

// Crypto 工具箱
// Crypto 工具箱 v2（MFCryptoToolbox.m）
- (void)mfCryptoGroupChanged:(UISegmentedControl *)seg { mfCryptoGroupChangedAction(seg); }
- (void)mfCryptoChipTapped:(UIButton *)chip { mfCryptoChipTappedAction(chip); }
- (void)mfCryptoRun:(UIButton *)btn { mfCryptoRunAction(btn); }
// 左滑操作入口（记录挂在 self 的 "mfSwipeRec"，不依赖按钮参数）
- (void)mfModifyResponseFromSwipe {
    MFNetRecord *rec = objc_getAssociatedObject(self, "mfSwipeRec");
    if (!rec) { mfToast(@"⚠️ 记录丢失"); return; }
    NSString *pattern = rec.url ?: @"";
    NSURL *u = [NSURL URLWithString:pattern];
    if (u.host.length > 0) pattern = [NSString stringWithFormat:@"%@://%@", u.scheme ?: @"https", u.host];
    mfShowRuleEditPage(pattern, @"replaceResp", -1, NO);
}
- (void)mfCopyRecordFromSwipe {
    MFNetRecord *rec = objc_getAssociatedObject(self, "mfSwipeRec");
    if (!rec) return;
    NSMutableString *t = [NSMutableString stringWithFormat:@"%@ %ld\nURL: %@",
        rec.method ?: @"?", (long)rec.status, rec.url ?: @"?"];
    if (rec.reqHeaders) [t appendFormat:@"\n\n【请求头】\n%@", rec.reqHeaders];
    if (rec.reqBody.length) { NSString *s = [[NSString alloc] initWithData:rec.reqBody encoding:NSUTF8StringEncoding]; if (s) [t appendFormat:@"\n\n【请求体】\n%@", s]; }
    if (rec.respHeaders) [t appendFormat:@"\n\n【响应头】\n%@", rec.respHeaders];
    if (rec.respBody.length) { NSString *s = [[NSString alloc] initWithData:rec.respBody encoding:NSUTF8StringEncoding]; if (s) [t appendFormat:@"\n\n【响应体】\n%@", s]; }
    [UIPasteboard generalPasteboard].string = t;
    mfToast(@"✅ 已复制整条记录");
}

@end

// ====== 主面板（四板块双列网格） ======
static void iaphShowPanel(UIViewController *vc) {
    if (g_mfPanelOverlay) return;
    if (!g_mfCtrl) g_mfCtrl = [[MFPanelCtrl alloc] init];
    @try {
        mfLog(@"PANEL STEP 1: vc=%@", NSStringFromClass([vc class]));
        UIWindow *keyWin = nil;
        if (@available(iOS 13.0, *)) {
            for (id sc in [UIApplication sharedApplication].connectedScenes) {
                if ([sc isKindOfClass:[UIWindowScene class]] && ((UIWindowScene *)sc).activationState == UISceneActivationStateForegroundActive) {
                    keyWin = [(UIWindowScene *)sc keyWindow]; break;
                }
            }
        }
        if (!keyWin) keyWin = [UIApplication sharedApplication].keyWindow;
        if (!keyWin) { mfLog(@"PANEL: NO keyWindow"); return; }
        mfLog(@"PANEL STEP 2: keyWin=%@", keyWin);

        CGRect sb = keyWin.bounds;
        UIView *overlay = [[UIView alloc] initWithFrame:sb];
        overlay.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        mfLog(@"PANEL STEP 3: overlay created");

        UIButton *mask = [UIButton buttonWithType:UIButtonTypeCustom];
        mask.frame = overlay.bounds;
        mask.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        mask.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.35];
        [mask addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClosePanel") forControlEvents:UIControlEventTouchUpInside];
        [overlay addSubview:mask];
        mfLog(@"PANEL STEP 4: mask added");

        CGFloat cardW = sb.size.width - 32;
        CGFloat cardH = 300;  // 主页紧凑——子页 push 时自动拉长
        g_mfCardW = cardW; g_mfCardH = cardH;
        g_mfHomeCardH = cardH;
        UIVisualEffectView *card = [[UIVisualEffectView alloc] initWithFrame:CGRectMake(16, (sb.size.height - cardH)/2, cardW, cardH)];
        card.effect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterial];
        card.layer.cornerRadius = 22;
        card.clipsToBounds = YES;
        g_mfCardView = card;
        UIView *content = card.contentView;
        g_mfCardContentView = content;
        mfLog(@"PANEL STEP 5: card created");

        // 主页内容容器——push 子页时隐藏它
        UIView *home = [[UIView alloc] initWithFrame:content.bounds];
        home.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [content addSubview:home];
        g_mfHomePage = home;

        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 12, 200, 26)];
        title.text = @"IAP工具箱";
        title.font = [UIFont boldSystemFontOfSize:18];
        title.textColor = [UIColor labelColor];
        [home addSubview:title];
        UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        closeBtn.frame = CGRectMake(cardW - 44, 10, 32, 32);
        [closeBtn setTitle:@"✕" forState:UIControlStateNormal];
        closeBtn.titleLabel.font = [UIFont systemFontOfSize:17];
        [closeBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClosePanel") forControlEvents:UIControlEventTouchUpInside];
        [home addSubview:closeBtn];
        mfLog(@"PANEL STEP 6: title+close added");

        CGFloat gw = (cardW - 32 - 12) / 2;
        CGFloat gy = 48;
        gy = mfGridButton(home, 16, gy, gw, @"数据分析", @"📡", @selector(mfShowDataAnalysisPage), NO, nil);
        mfLog(@"PANEL STEP 7a: dataAnalysis btn");
        gy = mfGridButton(home, 16 + gw + 12, gy - 92, gw, @"Product", @"🛍️", @selector(mfShowProductPage), NO, nil);
        mfLog(@"PANEL STEP 7b: product btn");
        // v2.6.21: 电池详情 + 实时日志 提到主页
        gy = mfGridButton(home, 16, gy, gw, @"电池详情", @"🔋", @selector(mfShowBatteryPage), NO, nil);
        gy = mfGridButton(home, 16 + gw + 12, gy - 92, gw, @"实时日志", @"📜", @selector(mfShowHostLogPage), NO, nil);
        // 网络修改已并入网络分析 → 规则管理 (v1.8.3)
        // Keychain 已并入 数据分析 板块 (v1.4.0)

        [overlay addSubview:card];
        g_mfPanelOverlay = overlay;
        g_mfPanelRootVC = vc;
        mfLog(@"PANEL STEP 8: overlay stored, g_mfCtrl=%p g_mfPanelOverlay=%p", g_mfCtrl, g_mfPanelOverlay);

        // v2.6.2: 独立 UIWindow——彻底解决 Telegram 等复杂 window 层级的触摸穿透
        {
            UIWindowScene *panelScene = keyWin.windowScene;
            if (!panelScene) panelScene = (UIWindowScene *)[[UIApplication sharedApplication].connectedScenes anyObject];
            g_mfPanelWindow = [[UIWindow alloc] initWithWindowScene:panelScene];
            g_mfPanelWindow.frame = keyWin.frame;
            g_mfPanelWindow.windowLevel = UIWindowLevelAlert + 1000;
            g_mfPanelWindow.backgroundColor = [UIColor clearColor];
            g_mfPanelWindow.rootViewController = [UIViewController new];
            g_mfPanelWindow.rootViewController.view = overlay;
            g_mfPanelWindow.hidden = NO;
            g_mfPanelWindow.userInteractionEnabled = YES;
        }
        mfLog(@"PANEL STEP 9: standalone UIWindow level=%.0f", g_mfPanelWindow.windowLevel);

        overlay.alpha = 0;
        [UIView animateWithDuration:0.25 animations:^{ overlay.alpha = 1; }];
        mfLog(@"PANEL STEP 10: animation started — DONE");
    } @catch (NSException *e) {
        mfLog(@"PANEL EXCEPTION: %@ %@\n%@", e.name, e.reason, e.callStackSymbols);
    }
}

// ====== ctor：注入入口 ======
static IMP orig_viewDidAppear;

// ====== IAP 收集（从 IAPHunter.m 合并） ======
static void ensureStoreKit(void) {
    if (NSClassFromString(@"SKProduct") != nil) return;
    dlopen("/System/Library/Frameworks/StoreKit.framework/StoreKit", RTLD_LAZY | RTLD_GLOBAL);
}

@interface MFIAPObserver : NSObject // v2.3.2 摘除协议声明(链接符号),方法动态分发等效
@end
@implementation MFIAPObserver
- (void)paymentQueue:(SKPaymentQueue *)queue updatedTransactions:(NSArray *)transactions {
    for (SKPaymentTransaction *t in transactions) {
        if (t.transactionState == SKPaymentTransactionStatePurchased ||
            t.transactionState == SKPaymentTransactionStateFailed) {
            [queue finishTransaction:t];
        }
    }
}
@end

// SK hooks——自动收集 productIdentifier
static IMP orig_SKProduct_pid;
static NSString *new_SKProduct_pid(id self, SEL _cmd) {
    NSString *r = ((NSString *(*)(id, SEL))orig_SKProduct_pid)(self, _cmd);
    if (r) {
        IAPRecord(r);
        extern void mfTopRecord(NSString *pid); // v2.11.3: 真实 SKProduct 响应对象 = 最高置信
        mfTopRecord(r);
        static NSMutableSet *logged = nil;
        if (!logged) logged = [NSMutableSet set];
        if (![logged containsObject:r]) { [logged addObject:r]; mfLog(@"[iap] SK1 SKProduct pid: %@", r); }
    }
    return r;
}
static IMP orig_SKPayment_pid;
static NSString *new_SKPayment_pid(id self, SEL _cmd) {
    NSString *r = ((NSString *(*)(id, SEL))orig_SKPayment_pid)(self, _cmd);
    if (r) { IAPRecord(r); mfLog(@"[iap] SK1 SKPayment pid: %@", r); }
    return r;
}
static IMP orig_SKPaymentTxn_pid;
static NSString *new_SKPaymentTxn_pid(id self, SEL _cmd) {
    NSString *r = ((NSString *(*)(id, SEL))orig_SKPaymentTxn_pid)(self, _cmd);
    if (r) { IAPRecord(r); mfLog(@"[iap] SK1 Transaction pid: %@", r); }
    return r;
}
static IMP orig_SKProductsReq_init;
// v2.11.3: 高置信 ID 单独归档(ProductsRequest 亲口要的 + 真实 SKProduct 响应) — 收据/dispatch 优先用
void mfTopRecord(NSString *pid) {
    if (pid.length == 0 || pid.length > 100) return;
    extern void mfFileIDsAdd(NSString *pid); // v2.11.8: 文件级主存储(防 defaults 被抹)
    mfFileIDsAdd(pid);
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSMutableArray *top = [NSMutableArray arrayWithArray:([d objectForKey:@"mfTopIDs"] ?: @[])];
    if ([top containsObject:pid]) return;
    [top removeObject:pid];
    [top insertObject:pid atIndex:0];
    if (top.count > 60) [top removeObjectsInRange:NSMakeRange(60, top.count - 60)];
    [d setObject:top forKey:@"mfTopIDs"]; [d synchronize];
    extern void mfReceiptForgeInvalidate(void);
    mfReceiptForgeInvalidate();
    mfLog(@"[iap] top id: %@ (total %lu)", pid, (unsigned long)top.count);
}
static id new_SKProductsReq_init(id self, SEL _cmd, NSSet *identifiers) {
    mfLog(@"[iap] SK1 ProductsRequest: %lu ids → %@", (unsigned long)identifiers.count, identifiers);
    // v2.11.7: 请求参数不再进 Top(未验证垃圾会占坑) — Top 只收 Apple 确认过的响应对象
    return ((id(*)(id, SEL, NSSet *))orig_SKProductsReq_init)(self, _cmd, identifiers);
}


// ====== StoreKit 2 侦察(v2.1.2):全量枚举 AppStoreKit 镜像类+方法表并落盘 ======
static void mfProbeStoreKit2(void) {
    NSMutableString *out = [NSMutableString stringWithCapacity:1 << 16];
    int clsCount = 0, methodCount = 0;
    // v2.52.3: objc_copyImageNames 原子快照 + strdup 自持拷贝
    // 2.52.2 用 _dyld_get_image_name(i) 逐索引取名——Scripting 这类动态 dlopen/dlclose
    // 的 app 在扫描期间卸载镜像 → dyld 名字串被释放 → strstr 踩悬挂指针(Real Crash 2026-09-06 #2)
    // 2.52.1 及以前是 objc_copyClassList 全进程 realize → Swift 泛型 conformance 空指针(Real Crash #1)
    unsigned ic2 = 0;
    const char **imgs = objc_copyImageNames(&ic2);
    if (!imgs || !ic2) { mfLog(@"[iap] SK2 枚举: 无镜像可枚举"); return; }
    char **safe = malloc(sizeof(char *) * ic2);
    for (unsigned i = 0; i < ic2; i++) safe[i] = strdup(imgs[i] ?: "");
    free(imgs);
    for (unsigned i = 0; i < ic2; i++) {
        const char *img = safe[i];
        if (!strstr(img, "AppStoreKit") && !strstr(img, "/StoreKit.framework")) continue;
        if (strstr(img, "StoreKitUI")) continue; // 排除商店 UI 框架降噪
        unsigned cn = 0;
        char **names = objc_copyClassNamesForImage(img, &cn);
        for (unsigned j = 0; j < cn; j++) {
            Class c = objc_getClass(names[j]);
            if (!c) continue;
            clsCount++;
            NSString *leaf = [NSString stringWithUTF8String:img].lastPathComponent;
            [out appendFormat:@"== %s  [%@]\n", names[j], leaf];
            for (int meta = 0; meta < 2; meta++) {
                Class cc = meta ? object_getClass(c) : c;
                unsigned mc = 0;
                Method *ms = class_copyMethodList(cc, &mc);
                for (unsigned k = 0; k < mc; k++) {
                    [out appendFormat:@"  %c %s\n", meta ? '+' : '-', sel_getName(method_getName(ms[k]))];
                    methodCount++;
                }
                free(ms);
            }
            [out appendString:@"\n"];
        }
        if (names) free(names);
    }
    for (unsigned i = 0; i < ic2; i++) free(safe[i]);
    free(safe);
    if (!clsCount) {
        mfLog(@"[iap] SK2 枚举: 进程内无 AppStoreKit 类——先打开一次购买页再扫描");
        return;
    }
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0]
                        stringByAppendingPathComponent:@"classdump"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *path = [dir stringByAppendingPathComponent:@"AppStoreKit_runtime.txt"];
    [out writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    mfLog(@"[iap] SK2 枚举: %d 类 / %d 方法 → %@", clsCount, methodCount, path);
}


// ====== SK2→SK1 桥拦截:已移除(v2.2.7) ======
// 两份 .ips 证明 receivedResponse: 只收 SK1 管线回声(含我们自己的验证请求),
// App 的 SK2 目录走纯 Swift 路径不经过此 ObjC 桥;而参数里全是 XPC 远端代理,
// 任何方法调用都可能"异常构建期二次抛出"→SIGABRT。
// 零收益全风险 → 整体拆除。SK2 App 的 ID 获取依赖:静态扫描+缓存扫描+网络提取+SK验证。

static void swizzle(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (origOut) *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

// TestFlight 增强已迁出 → MFTestFlightHooks.m(AppHooks.dylib,v2.4.0 按注入目标归位)


// ====== 自动添加新安装 App 到白名单 ======
// 监听 SpringBoard 的应用安装/注册通知

static void mfAutoApplyAdd(NSString *bid) {
    if (!mfPrefBool(@"mfIAPAutoApply", NO)) return;
    if (bid.length == 0) return;
    mfLog(@"autoApply: adding %@ to whitelist", bid);
    @autoreleasepool {
        NSUserDefaults *d = [[NSUserDefaults alloc] initWithSuiteName:@"com.linsars.minisfix"];
        NSMutableArray *list = [NSMutableArray arrayWithArray:([d objectForKey:@"mfIAPAppList"] ?: @[])];
        if (![list containsObject:bid]) {
            [list addObject:bid];
            [d setObject:list forKey:@"mfIAPAppList"];
            [d synchronize];
            mfLog(@"autoApply: %@ added successfully", bid);
        } else {
            mfLog(@"autoApply: %@ already in list", bid);
        }
    }
}

// 监听应用安装相关通知
static void mfObserveAppInstallNotifications(void) {
    mfLog(@"autoApply: observing notifications");
    // 通知名列表（SpringBoard/installd 会发送这些通知）
    NSArray *notifNames = @[
        @"com.apple.LaunchServices.applicationRegistered",
        @"com.apple.LaunchServices.applicationStateChanged",
        @"SBInstalledApplicationsDidChangeNotification",
        @"com.apple.mobile.application_installed",
        @"com.apple.mobile.installation.changed",
    ];
    for (NSString *name in notifNames) {
        [[NSNotificationCenter defaultCenter] addObserverForName:name
            object:nil queue:nil usingBlock:^(NSNotification *note) {
                mfLog(@"autoApply: notification %@ received", name);
                if (!mfPrefBool(@"mfIAPAutoApply", NO)) return;
                // 尝试从通知获取 bundleId
                NSString *bid = nil;
                // 方式1: userInfo 中的 bundleId
                bid = note.userInfo[@"bundleIdentifier"] ?: note.userInfo[@"bundleId"] ?: note.userInfo[@"SBApplicationBundleIdentifier"];
                // 方式2: 从 LSApplicationProxy 获取
                if (!bid && note.object) {
                    if ([note.object respondsToSelector:@selector(bundleIdentifier)]) {
                        bid = [note.object performSelector:@selector(bundleIdentifier)];
                    } else if ([note.object isKindOfClass:[NSDictionary class]]) {
                        bid = ((NSDictionary *)note.object)[@"MCMMetadataIdentifier"] ?: ((NSDictionary *)note.object)[@"CFBundleIdentifier"];
                    }
                }
                mfLog(@"autoApply: notification bid=%@", bid ?: @"nil");
                if (bid) mfAutoApplyAdd(bid);
            }];
        mfLog(@"autoApply: observing %@", name);
    }
    // 额外: hook LSApplicationWorkspace 的 registerApplicationDictionary:
    Class ws = objc_getClass("LSApplicationWorkspace");
    if (ws) {
        SEL sel = NSSelectorFromString(@"registerApplicationDictionary:");
        Method m = class_getInstanceMethod(ws, sel);
        if (m) {
            IMP orig = method_getImplementation(m);
            method_setImplementation(m, imp_implementationWithBlock(^BOOL(id self, NSDictionary *dict) {
                mfLog(@"autoApply: registerApplicationDictionary called");
                if (mfPrefBool(@"mfIAPAutoApply", NO)) {
                    NSString *bid = dict[@"MCMMetadataIdentifier"] ?: dict[@"CFBundleIdentifier"];
                    mfLog(@"autoApply: registerApp bid=%@", bid ?: @"nil");
                    if (bid) mfAutoApplyAdd(bid);
                }
                // v2.17.2 修复: 原方法返回 BOOL, void block 会把返回值炸成垃圾 → 巨魔注册恒失败(181)
                return ((BOOL(*)(id, SEL, NSDictionary *))orig)(self, sel, dict);
            }));
            mfLog(@"autoApply: registerApplicationDictionary hooked");
        }
    }
}

static void mfInstallAutoApply(void) {
    mfLog(@"autoApply: installing, pid=%d app=%@", getpid(), [[NSBundle mainBundle] bundleIdentifier]);
    mfObserveAppInstallNotifications();
}

// 双指长按手势处理
static void mfLongPressAction(id self, SEL _cmd, UILongPressGestureRecognizer *g) {
    if (g.state != UIGestureRecognizerStateBegan) return;
    mfLog(@"LONGPRESS BEGAN touches=%lu", (unsigned long)g.numberOfTouches);
    if (g_mfPanelOverlay) { mfLog(@"panel already open, skip"); return; }
    iaphShowPanel((UIViewController *)self);
    mfLog(@"LONGPRESS iaphShowPanel called");
}

static void new_viewDidAppear(id self, SEL _cmd, BOOL animated) {
    ((void(*)(id, SEL, BOOL))orig_viewDidAppear)(self, _cmd, animated);
    static const char kLPKey = 0;
    if (objc_getAssociatedObject(self, &kLPKey) == nil) {
        UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(mfHandleLongPress:)];
        lp.minimumPressDuration = 0.5;
        lp.numberOfTouchesRequired = 2;
        UIViewController *vc = (UIViewController *)self;
        [vc.view addGestureRecognizer:lp];
        objc_setAssociatedObject(self, &kLPKey, @"1", OBJC_ASSOCIATION_RETAIN);
        mfLog(@"gesture added to %@", NSStringFromClass([self class]));
    }
}

#define IAPTOOLS_VERSION @"2.7.3"

__attribute__((constructor)) static void MinisFixCtor(void) {
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        // v2.4.0 系统进程守卫（必须最先执行）：本 dylib 只服务用户 App 的 IAP工具箱面板,
        // Apple 进程(含 SpringBoard/TestFlight)一律不装任何 hook。
        // SpringBoard 系统功能在 FolderX.dylib,TF/商店 hook 在 AppHooks.dylib(见 ARCHITECTURE.md)
        if (bid.length == 0 || [bid.lowercaseString hasPrefix:@"com.apple."]) return;
        mfLog(@"=== IAPtools ctor ENTER pid=%d app=%@ version=%@ ===", getpid(), bid, IAPTOOLS_VERSION);

        // 自动添加新 App 到白名单（始终注册通知，运行时检查开关）
        mfLog(@"autoApply: installing observers");
        mfInstallAutoApply();

        // 启用检查：设置页「启用 IAP工具箱」×「应用程序」白名单（不通过则不加载任何功能）
        if (!mfIsEnabledForCurrentApp()) {
            mfLog(@"app not in IAP工具箱 whitelist — MinisFix disabled in this app");
            return;
        }

        // v2.6.1: 移除 5s 错峰(v2.3.2 为 BT panic 加的,根因=硬依赖链已 dlopen 化修复)
        // v2.6.17: 宿主日志(pipe+dup2)——开关默认 OFF,开过则冷启动即接管 fd
        if (mfPrefBool(@"mfHostLogEnabled", NO)) {
            mfHostLogStart();
        }
        // v2.6.85: CloudKit once 预热——有 iCloud entitlement 的 app 启动时后台预热 CK
        // （点按钮时才首调 CK = once 运行中途触发 = SIGTRAP @ CK+0x9e89c，三次复现实锤）
        mfCloudKitWarmupStart();
        // 实时捕获(v2.2.8):默认 OFF;用户开过则持久化,冷启动即装协议——
        // 解决"启动后才开开关截不到老会话"(v2.0.2 一刀切留下的坑)
        // v2.56.3: per-app——读 mfCaptureEnabled_<bid>(每个 app 独立, 冷启动按各自键恢复)
        NSString *capKey = [NSString stringWithFormat:@"mfCaptureEnabled_%@", [[NSBundle mainBundle] bundleIdentifier]];
        if (mfPrefBool(capKey, NO)) {
            g_captureEnabled = YES;
            extern void mfInstallNetworkCapture(void);
            mfInstallNetworkCapture();
            mfLog(@"capture restored from pref — active from launch");
        }

        // SK2→SK1 桥拦截（SK2 App 的产品目录必经之路）

        // IAP 收集
        ensureStoreKit();
        Class SKProductCls = NSClassFromString(@"SKProduct");
        if (SKProductCls) {
            swizzle(SKProductCls, @selector(productIdentifier), (IMP)new_SKProduct_pid, &orig_SKProduct_pid);
            swizzle(NSClassFromString(@"SKPayment"), @selector(productIdentifier), (IMP)new_SKPayment_pid, &orig_SKPayment_pid);
            swizzle(NSClassFromString(@"SKPaymentTransaction"), @selector(productIdentifier), (IMP)new_SKPaymentTxn_pid, &orig_SKPaymentTxn_pid);
            swizzle(NSClassFromString(@"SKProductsRequest"), @selector(initWithProductIdentifiers:), (IMP)new_SKProductsReq_init, &orig_SKProductsReq_init);
            mfLog(@"ctor SK hooks installed");
        }
        // 交易观察器（finishTransaction）
        static MFIAPObserver *g_observer = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            g_observer = [[MFIAPObserver alloc] init];
            [[objc_getClass("SKPaymentQueue") defaultQueue] addTransactionObserver:g_observer];
        });

        // v2.6.48: ObjC 规则冷启动自动应用(每个注入的 app 进程生效——跨进程规则的根基)
        extern void mfReflixOracleStart(void);
        mfReflixOracleStart();
        extern void mfProcCaptureStart(void);   // v2.26.0: 第二拳·被动点位采集(白名单 app)
        mfProcCaptureStart();
        extern void mfAppPatchBoot(void);       // v2.58: 判定点引擎(mfEntDumps 自判, 无开关)
        mfAppPatchBoot();
        extern void mfChainABootReplay(void);   // v2.59.4: 链A 直写规则冷启动重打(3s 延迟)
        mfChainABootReplay();
        mfObjCHookApplySilent();
        mfSubInjectAutoStart();
        mfReceiptForgeAutoStart();

        // 手势注册
        Class vcCls = NSClassFromString(@"UIViewController");
        if (vcCls) {
            Method m = class_getInstanceMethod(vcCls, @selector(viewDidAppear:));
            if (m) {
                orig_viewDidAppear = method_getImplementation(m);
                method_setImplementation(m, (IMP)new_viewDidAppear);
                mfLog(@"ctor viewDidAppear swizzled");
            }
            class_addMethod(vcCls, @selector(mfHandleLongPress:), (IMP)mfLongPressAction, "v@:@");
            mfLog(@"ctor longPress method added");
        }

        extern void mfFileIDsDiag(void);
        mfFileIDsDiag();
        extern void mfL0CtorInstall(void);
        mfL0CtorInstall();   // v2.49.2: L0 hook ctor 装配(observer 记录必须赶在 app 注册前)
        mfLog([NSString stringWithFormat:@"=== IAPtools ctor DONE (build %s) ===", MF_BUILD_VER_S]);
    }
}