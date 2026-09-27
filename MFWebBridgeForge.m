// MFWebBridgeForge.m — L3 WebView JS 桥权益改写引擎 (v2.58.191)
// 【归属】IAPtools.dylib (IAP 域); 实验模拟页开关; ctor 自启动
// 【背景】(dbg_179 mailnow 定谳): 一整类 WebView 壳 app(界面是网页, native 是壳)。
//   权益状态由服务器通过 JS 桥(WKScriptMessageHandler)在网页加载时下发给 native:
//   如 mailnow 的 FlexCall action=loadSuccess;...premium=0;no_ad=0; → native 据此显示
//   广告 banner + 锁 native 会员 UI。
//   服务端网页【内容】本地无解(会员功能是服务器按账户 session 渲染的), 但 native 侧读的
//   桥消息【本地可改写】→ 关广告 + 解 native 会员 UI 门。这是"服务端型也有本地可做的部分"。
// 【机理】swizzle -[WKScriptMessage body](WebKit 类, 运行时取): 桥消息 body 流到 app 处理器前,
//   扫其中"权益键=假值"(premium=0 / no_ad=0 / vip=false ...)→ 改写成真值(=1 / true)。
//   - body 是 NSString(FlexCall 型 "k=v;k=v;")→ 逐键改值
//   - body 是 NSDictionary(现代 JS 桥 postMessage 对象)→ 递归改权益键值
//   - 非权益内容原样透传(内容门控, 零副作用)
// 【app-agnostic】零 app 硬编码: 权益键表通用(premium/no_ad/vip/is_pro/subscribed/unlock...),
//   桥类是标准 WebKit WKScriptMessage, 不写死任何 app 的桥名(FlexCall 等)。
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "MFPanel.h"

#define wbLog(fmt, ...) mfLog((fmt), ##__VA_ARGS__)

static BOOL g_wbOn = NO;
static long g_wbHits = 0;              // 改写次数
static long g_wbSeen = 0;              // 见到权益桥消息次数
static IMP  g_origBody = NULL;

// 权益键(小写子串) — JS 桥下发权益态常用键名, 通用零 app 硬编码
static const char *kWbEntKeys[] = {
    "premium", "no_ad", "noad", "vip", "is_pro", "ispro", "pro_status", "prostatus",
    "ispremium", "haspremium", "subscribed", "is_subscriber", "issubscriber",
    "unlocked", "is_unlock", "purchased", "membership", "isvip", "hasvip",
    "premium_status", "no_ads", "hide_ad", "hideads", "adfree", "ad_free", "is_paid", "ispaid",
};
static const int kWbEntKeyN = (int)(sizeof(kWbEntKeys)/sizeof(kWbEntKeys[0]));

static BOOL wbKeyIsEnt(NSString *k) {
    if (![k isKindOfClass:[NSString class]] || !k.length) return NO;
    const char *c = [[k lowercaseString] UTF8String];
    if (!c) return NO;
    for (int i = 0; i < kWbEntKeyN; i++) if (strstr(c, kWbEntKeys[i])) return YES;
    return NO;
}

// 字符串形态桥消息(k=v;k=v; 或 k:v&k:v) — 把权益键的假值改真值
static NSString *wbRewriteString(NSString *s, BOOL *changed) {
    if (![s isKindOfClass:[NSString class]] || s.length < 3) return s;
    // 只在整串含任一权益键时才拆分处理(省开销)
    BOOL maybe = NO;
    { const char *c = [[s lowercaseString] UTF8String];
      if (c) for (int i = 0; i < kWbEntKeyN; i++) if (strstr(c, kWbEntKeys[i])) { maybe = YES; break; } }
    if (!maybe) return s;
    // 分隔符探测: ';' 优先(FlexCall), 否则 '&'
    NSString *sep = [s containsString:@";"] ? @";" : ([s containsString:@"&"] ? @"&" : nil);
    if (!sep) return s;
    NSArray *parts = [s componentsSeparatedByString:sep];
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:parts.count];
    BOOL any = NO;
    for (NSString *p in parts) {
        NSRange eq = [p rangeOfString:@"="];
        if (eq.location == NSNotFound) eq = [p rangeOfString:@":"];
        if (eq.location == NSNotFound) { [out addObject:p]; continue; }
        NSString *k = [p substringToIndex:eq.location];
        NSString *v = [p substringFromIndex:eq.location + 1];
        NSString *vt = [[v stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]] lowercaseString];
        BOOL isFalse = [vt isEqualToString:@"0"] || [vt isEqualToString:@"false"] || [vt isEqualToString:@"no"] || [vt isEqualToString:@""];
        if (wbKeyIsEnt(k) && isFalse) {
            NSString *nv = ([vt isEqualToString:@"false"]) ? @"true" : ([vt isEqualToString:@"no"] ? @"yes" : @"1");
            [out addObject:[NSString stringWithFormat:@"%@%@%@", k, [p characterAtIndex:eq.location] == ':' ? @":" : @"=", nv]];
            any = YES;
        } else [out addObject:p];
    }
    if (!any) return s;
    *changed = YES;
    return [out componentsJoinedByString:sep];
}

// 字典形态桥消息 — 递归改权益键的假值
static id wbRewriteObject(id obj, BOOL *changed) {
    if ([obj isKindOfClass:[NSString class]]) return wbRewriteString(obj, changed);
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *m = [obj mutableCopy];
        for (NSString *k in [(NSDictionary *)obj allKeys]) {
            id v = m[k];
            if (wbKeyIsEnt(k)) {
                if ([v isKindOfClass:[NSNumber class]] && ![v boolValue]) { m[k] = @1; *changed = YES; continue; }
                if ([v isKindOfClass:[NSString class]]) {
                    NSString *vt = [[v lowercaseString] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                    if ([vt isEqualToString:@"0"]||[vt isEqualToString:@"false"]||[vt isEqualToString:@"no"]||!vt.length) {
                        m[k] = ([vt isEqualToString:@"false"])?@"true":([vt isEqualToString:@"no"]?@"yes":@"1"); *changed = YES; continue;
                    }
                }
            }
            id nv = wbRewriteObject(v, changed);   // 递归(嵌套 dict/array)
            if (nv) m[k] = nv;
        }
        return m;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableArray *a = [obj mutableCopy];
        for (NSUInteger i = 0; i < a.count; i++) { id nv = wbRewriteObject(a[i], changed); if (nv) a[i] = nv; }
        return a;
    }
    return obj;
}

// swizzled -[WKScriptMessage body]
static id wb_body(id self, SEL _cmd) {
    id b = g_origBody ? ((id(*)(id,SEL))g_origBody)(self, _cmd) : nil;
    if (!g_wbOn || !b) return b;
    BOOL changed = NO;
    id nb = wbRewriteObject(b, &changed);
    if (changed) {
        g_wbSeen++; g_wbHits++;
        NSString *desc = [b isKindOfClass:[NSString class]] ? b : [b description];
        if (desc.length > 100) desc = [desc substringToIndex:100];
        wbLog(@"[wbforge] ★桥权益改写 #%ld: %@ → 真值", g_wbHits, desc);
        return nb;
    }
    return b;
}

void mfWebBridgeForgeEnable(void) {
    if (g_wbOn) return;
    if (!g_origBody) {
        Class WK = objc_getClass("WKScriptMessage");
        if (!WK) { wbLog(@"[wbforge] WKScriptMessage 类缺失(app 无 WebView?) — 跳过"); return; }
        Method m = class_getInstanceMethod(WK, @selector(body));
        if (!m) { wbLog(@"[wbforge] -[WKScriptMessage body] 方法缺失 — 跳过"); return; }
        g_origBody = method_setImplementation(m, (IMP)wb_body);
        wbLog(@"[wbforge] hook 装配: -[WKScriptMessage body] swizzled");
    }
    g_wbOn = YES;
    [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"mfWebBridgeForgeEnabled"];
    wbLog(@"[wbforge] ON");
}
void mfWebBridgeForgeDisable(void) {
    g_wbOn = NO;   // swizzle 保留(透传原实现), 只关改写
    [[NSUserDefaults standardUserDefaults] setBool:NO forKey:@"mfWebBridgeForgeEnabled"];
    wbLog(@"[wbforge] OFF");
}
void mfWebBridgeForgeSwitchChanged(UISwitch *sw) {
    if (sw.on) { mfWebBridgeForgeEnable(); mfToast(@"🌉 WebView 桥权益改写已开 · 重启 app 生效"); }
    else { mfWebBridgeForgeDisable(); mfToast(@"⏹️ WebView 桥权益改写已关"); }
}
void mfWebBridgeForgeAutoStart(void) {
    if (![[NSUserDefaults standardUserDefaults] boolForKey:@"mfWebBridgeForgeEnabled"]) return;
    mfWebBridgeForgeEnable();
    wbLog(@"[wbforge] AutoStart ON");
}
long mfWebBridgeForgeHits(void) { return g_wbHits; }
BOOL mfWebBridgeForgeIsOn(void) { return g_wbOn; }
