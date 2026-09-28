// MFWebBridgeForge.m — WebForge WebView 权益引擎 (v2.58.195; 原 "L3 桥改写" 升级)
// 【归属】IAPtools.dylib (IAP 域); ctor 自启动 + 判型总闸自动派发。
// 【定位】WebView / 服务端权益型 app 的本地解 —— 网络分析(NSURLProtocol)只能拦 app 原生
//   NSURLSession, 拦不到 WKWebView 网页内 JS 的 fetch/XHR(独立 Networking 进程)。WebForge
//   在网页 JS 环境里补上这一层, 与网络分析互补: 原生请求→网络分析, 网页请求→WebForge。
// 【两条腿】
//   腿A(桥消息): swizzle -[WKScriptMessage body] — postMessage 桥型(mailnow FlexCall
//     "premium=0;no_ad=0" 型), 桥消息流到 app 处理器前改权益键假值→真。
//   腿B(响应改写): swizzle -[WKWebView init...] → WKUserScript(DocStart)注入通用引擎,
//     hook 网页 fetch/XHR 改接口响应(啪啪搜 /user/my 判 vip 型, 源自 Rusku 实证架构)。
// 【抓改一体·app-agnostic】代码通用, app 特定的只有"规则数据"不是代码:
//   · 抓: 注入 JS 解码每个响应 → mfwebcap 桥回传 → [webcap]实时日志 + 并进网络分析记录
//   · 荐: 自动扫响应里"权益键=假值"字段 → 生成 webrules 建议(webrules_suggested_<bid>.json)
//   · 改: webrules_<bid>.json 规则(点路径→值)自动改包, 编码自适应(明文/base64反转/base64)
//   · 后门: webforge_<bid>.js 完全自定义 JS(高级, 编码/逻辑特殊时完整接管)
// 【零 app 硬编码】权益键表通用; 桥类是标准 WebKit; app 专属逻辑全在外部数据文件, 不进包。
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

// ============ v2.58.195: L3 第二条腿 — WKUserScript 注入引擎(fetch/XHR 响应改写) ============
// 【为何】L3 原只 swizzle -[WKScriptMessage body](postMessage 桥型, 如 mailnow FlexCall)。
//   另一大类 WebView 壳(如啪啪搜)权益判定走网页内 fetch/XHR 拿接口响应(/user/my)判 vip,
//   不经 WKScriptMessage 桥 → body swizzle 完全无效。这类要在网页 JS 环境里 hook
//   fetch/XHR 改响应体 —— 用 WKUserScript(DocumentStart)注入(源自 Rusku 实证架构)。
// 【注入内容优先级】外部 per-app 文件 > 外部全局文件 > 内置通用层:
//   /var/jb/var/mobile/minisfix/webforge_<bid>.js  (针对性 JS, 放 app 专属解锁, 编码特殊/接口特定必走此)
//   /var/jb/var/mobile/minisfix/webforge.js         (全局自定义)
//   内置通用层(明文 JSON 响应扫权益键假值→真; base64/特殊编码型必须走外部文件)
// 【app-agnostic】引擎零 app 硬编码; app 专属逻辑(接口路径/字段/编码)在外部 JS 文件, 不进包。
static BOOL g_wfOn = NO;
static BOOL g_wfCap = YES;              // 抓包上报(默认开: 先抓才知道改什么)
static IMP g_wfOrigInitFrame = NULL;
static IMP g_wfOrigInitCoder = NULL;
static char kWFInjectedKey;
static long g_wfInjected = 0;
static long g_wfCapN = 0;

// 抓包回传 handler(duck-typed WKScriptMessageHandler, 不硬链 WebKit):
//   注入 JS 把每个响应解码后 postMessage 到 mfwebcap → 这里 ①打 [webcap] 实时日志
//   ②并进网络分析记录列表 ③自动分析候选权益字段 → 生成 webrules 建议(落盘, 用户采纳即用)。
@interface MFWebCapHandler : NSObject
@end

// 累积: url → 候选点路径集合(值为假的权益键)。跨消息累积, 落盘 webrules_suggested_<bid>.json
static NSMutableDictionary *g_wfSuggest = nil;

// 递归找"权益键 && 值为假(0/false/空/no)"的点路径 → 收进 out(如 "data.vip")
static void mfWFHarvest(id obj, NSString *prefix, NSMutableArray *out) {
    if ([obj isKindOfClass:[NSDictionary class]]) {
        for (NSString *k in [(NSDictionary *)obj allKeys]) {
            id v = ((NSDictionary *)obj)[k];
            NSString *path = prefix.length ? [NSString stringWithFormat:@"%@.%@", prefix, k] : k;
            BOOL isFalse = NO;
            if ([v isKindOfClass:[NSNumber class]]) isFalse = ![v boolValue];
            else if ([v isKindOfClass:[NSString class]]) {
                NSString *t = [[v lowercaseString] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                isFalse = [t isEqualToString:@"0"]||[t isEqualToString:@"false"]||[t isEqualToString:@"no"]||!t.length;
            }
            if (wbKeyIsEnt(k) && isFalse && ![v isKindOfClass:[NSDictionary class]] && ![v isKindOfClass:[NSArray class]])
                [out addObject:path];
            else
                mfWFHarvest(v, path, out);   // 递归嵌套
        }
    } else if ([obj isKindOfClass:[NSArray class]]) {
        NSArray *a = obj;
        for (NSUInteger i = 0; i < a.count && i < 20; i++)
            mfWFHarvest(a[i], [NSString stringWithFormat:@"%@.%lu", prefix, (unsigned long)i], out);
    }
}

// 把累积的候选写成可直接用的 webrules 建议文件(值统一给"真值": 数字→1, 也附 expdate 远期样例)
static void mfWFWriteSuggest(void) {
    if (!g_wfSuggest.count) return;
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"app";
    NSMutableArray *rules = [NSMutableArray array];
    for (NSString *u in g_wfSuggest) {
        NSArray *paths = [(NSSet *)g_wfSuggest[u] allObjects];
        if (!paths.count) continue;
        NSMutableDictionary *set = [NSMutableDictionary dictionary];
        for (NSString *p in paths) set[p] = @1;   // 权益键假值→1(用户可自行改成 true/字符串)
        [rules addObject:@{@"u": u, @"set": set}];
    }
    NSData *d = [NSJSONSerialization dataWithJSONObject:rules options:NSJSONWritingPrettyPrinted error:nil];
    if (!d) return;
    NSString *path = [NSString stringWithFormat:@"/var/jb/var/mobile/minisfix/webrules_suggested_%@.json", bid];
    [d writeToFile:path atomically:YES];
    wbLog(@"[webforge] 📝 已更新规则建议 %lu 条 → %@ (采纳: 改名为 webrules_%@.json)", (unsigned long)rules.count, path, bid);
}

@implementation MFWebCapHandler
- (void)userContentController:(id)ucc didReceiveScriptMessage:(id)msg {
    @try {
        id b = ((id(*)(id,SEL))objc_msgSend)(msg, sel_registerName("body"));
        NSString *s = [b isKindOfClass:[NSString class]] ? (NSString *)b : [b description];
        g_wfCapN++;
        // ① 实时日志
        NSString *disp = s.length > 2000 ? [s substringToIndex:2000] : s;
        wbLog(@"[webcap] #%ld %@", g_wfCapN, disp);
        // 解析 {u,e,b}
        NSData *jd = [s dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *env = jd ? [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil] : nil;
        if (![env isKindOfClass:[NSDictionary class]]) return;
        NSString *url = env[@"u"]; id body = env[@"b"];
        // ② 并进网络分析记录(与原生请求同列表, 一处看全部流量)
        extern void mfNetAddWebCapRecord(NSString *url, NSString *enc, id bodyJSON);
        mfNetAddWebCapRecord(url ?: @"?", env[@"e"], body);
        // ③ 自动生成规则候选
        NSMutableArray *cand = [NSMutableArray array];
        mfWFHarvest(body, @"", cand);
        if (cand.count && url.length) {
            if (!g_wfSuggest) g_wfSuggest = [NSMutableDictionary dictionary];
            NSMutableSet *set = g_wfSuggest[url] ?: [NSMutableSet set];
            NSUInteger before = set.count;
            [set addObjectsFromArray:cand];
            g_wfSuggest[url] = set;
            if (set.count > before) {   // 有新候选才落盘 + 提示
                wbLog(@"[webforge] 🎯 %@ 发现权益候选字段: %@", url, [cand componentsJoinedByString:@","]);
                mfWFWriteSuggest();
            }
        }
    } @catch (__unused NSException *e) {}
}
@end
static id g_wfCapHandler = nil;

// ============ 通用注入引擎(app-agnostic): 抓包 + 规则驱动改包 ============
// 一份 JS 通吃所有 WebView / 服务器权益型 app。app 特定的只有"规则数据"(webrules_<bid>.json),
// 不是代码 —— 这才是"服务器权益型不再是死区"的通解: 抓响应 → 写规则 → 自动改, 零 JS。
//   · 编码自适应: 明文 JSON / base64 整串反转(atob 型) / 直接 base64 —— decode + 对称 encode
//   · 抓包: 每个响应解码后经 mfwebcap 桥回传 → [webcap] 进实时日志(看 app 传什么/哪个字段是权益)
//   · 改包: 按规则表(window.__MFR)对匹配 url 的响应 JSON 改字段(点路径 data.vip), 重编码塞回
//   · 规则格式: [{"u":"/user/my","set":{"data.vip":1,"data.expdate":"2999"}}] —— 纯数据零 JS
static NSString *mfWFBuiltinJS(void) {
    return
    @"(function(){'use strict';"
    @"var R=window.__MFR||[];var C=window.__MFCAP;"
    @"function rev(s){return s.split('').reverse().join('');}"
    @"function b2b(b){var s='';for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s);}"
    @"function u2b(s){var b=atob(s),o=new Uint8Array(b.length);for(var i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o;}"
    @"function asc(o){return JSON.stringify(o).replace(/[\\u007f-\\uffff]/g,function(c){return '\\\\u'+('0000'+c.charCodeAt(0).toString(16)).slice(-4);});}"
    @"function dec(t){t=(''+t).trim();if(!t)return null;"
    @"if(t.charAt(0)=='{'||t.charAt(0)=='['){try{return{j:JSON.parse(t),e:'plain'};}catch(e){return null;}}"
    @"try{var r=rev(t),p='';while(r.charAt(0)=='='){p+='=';r=r.slice(1);}r=r.replace(/-/g,'+').replace(/_/g,'/').replace(/[^A-Za-z0-9+/]/g,'')+p;while(r.length%4)r+='=';var s=new TextDecoder().decode(u2b(r)).replace(/\\u0000+$/,'');if(s.charAt(0)=='{'||s.charAt(0)=='[')return{j:JSON.parse(s),e:'rb64'};}catch(e){}"
    @"try{var s2=new TextDecoder().decode(u2b(t));if(s2.charAt(0)=='{'||s2.charAt(0)=='[')return{j:JSON.parse(s2),e:'b64'};}catch(e){}"
    @"return null;}"
    @"function enc(j,e){if(e=='rb64')return rev(b2b(new TextEncoder().encode(asc(j))));if(e=='b64')return b2b(new TextEncoder().encode(asc(j)));return JSON.stringify(j);}"
    @"function sp(o,path,v){var k=(''+path).split('.'),c=o;for(var i=0;i<k.length-1;i++){if(typeof c[k[i]]!='object'||c[k[i]]==null)c[k[i]]={};c=c[k[i]];}c[k[k.length-1]]=v;}"
    @"function cap(u,d){if(!C)return;try{webkit.messageHandlers.mfwebcap.postMessage(JSON.stringify({u:u,e:d.e,b:d.j}).slice(0,4000));}catch(e){}}"
    @"function app(u,j){var h=false;for(var i=0;i<R.length;i++){var r=R[i];if((''+u).indexOf(r.u)<0)continue;if(r.set)for(var p in r.set){sp(j,p,r.set[p]);h=true;}}return h;}"
    @"function proc(u,t){var d;try{d=dec(t);}catch(e){d=null;}if(!d)return null;cap(u,d);var h=app(u,d.j);if(!h)return null;try{return enc(d.j,d.e);}catch(e){return null;}}"
    @"try{if(window.fetch){var of=window.fetch.bind(window);window.fetch=function(){var a=arguments,u=typeof a[0]=='string'?a[0]:((a[0]&&a[0].url)||'');return of.apply(window,a).then(function(r){try{return r.clone().text().then(function(t){var n=proc(u,t);if(n==null)return r;return new Response(n,{status:r.status,statusText:r.statusText,headers:r.headers});}).catch(function(){return r;});}catch(e){return r;}});};}}catch(e){}"
    @"try{var NX=window.XMLHttpRequest;if(NX){var W=function(){var x=new NX(),u='';var no=x.open;x.open=function(m,url){u=''+url;return no.apply(x,arguments);};try{x.addEventListener('readystatechange',function(){try{if(x.readyState==4){var n=proc(u,x.responseText);if(n!=null){Object.defineProperty(x,'responseText',{configurable:true,get:function(){return n;}});Object.defineProperty(x,'response',{configurable:true,get:function(){return n;}});}}}catch(e){}},true);}catch(e){}return x;};W.prototype=NX.prototype;window.XMLHttpRequest=W;}}catch(e){}"
    @"})();";
}

// 注入源: 完全自定义 JS(webforge_<bid>.js / webforge.js, 高级用户完整控制)
//        > 通用引擎 + 外部规则数据(webrules_<bid>.json / webrules.json, 只写 {url,字段,值})
static NSString *mfWFScript(void) {
    NSString *dir = @"/var/jb/var/mobile/minisfix";
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    // 1) 完全自定义 JS 后门(高级: 编码特殊/逻辑复杂时完整接管)
    NSString *custom = [NSString stringWithContentsOfFile:[dir stringByAppendingPathComponent:[NSString stringWithFormat:@"webforge_%@.js", bid]] encoding:NSUTF8StringEncoding error:nil];
    if (!custom.length) custom = [NSString stringWithContentsOfFile:[dir stringByAppendingPathComponent:@"webforge.js"] encoding:NSUTF8StringEncoding error:nil];
    if (custom.length) { wbLog(@"[webforge] 用自定义 JS (%lu B)", (unsigned long)custom.length); return custom; }
    // 2) 通用引擎 + 外部规则数据(常规路径: 用户只写规则, 不碰 JS/编码)
    NSString *rules = [NSString stringWithContentsOfFile:[dir stringByAppendingPathComponent:[NSString stringWithFormat:@"webrules_%@.json", bid]] encoding:NSUTF8StringEncoding error:nil];
    if (!rules.length) rules = [NSString stringWithContentsOfFile:[dir stringByAppendingPathComponent:@"webrules.json"] encoding:NSUTF8StringEncoding error:nil];
    if (!rules.length) rules = @"[]";
    NSDictionary *pf = [NSDictionary dictionaryWithContentsOfFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"] ?: @{};
    g_wfCap = pf[@"mfWebForgeCap"] ? [pf[@"mfWebForgeCap"] boolValue] : YES;
    NSString *header = [NSString stringWithFormat:@"window.__MFR=%@;window.__MFCAP=%@;", rules, g_wfCap ? @"true" : @"false"];
    wbLog(@"[webforge] 通用引擎 + 规则 %lu B cap=%d", (unsigned long)rules.length, g_wfCap);
    return [header stringByAppendingString:mfWFBuiltinJS()];
}

// 往一个 WKWebViewConfiguration 的 userContentController 注入 WKUserScript(DocStart) + 抓包 handler
static void mfWFInject(id cfg) {
    if (!cfg) return;
    id ucc = ((id(*)(id,SEL))objc_msgSend)(cfg, sel_registerName("userContentController"));
    if (!ucc) {
        Class UCC = objc_getClass("WKUserContentController");
        if (!UCC) return;
        ucc = ((id(*)(id,SEL))objc_msgSend)((id)UCC, sel_registerName("new"));
        ((void(*)(id,SEL,id))objc_msgSend)(cfg, sel_registerName("setUserContentController:"), ucc);
    }
    if (objc_getAssociatedObject(ucc, &kWFInjectedKey)) return;   // 防同一 ucc 重复注入
    // 抓包桥 mfwebcap: 注入 JS 把解码后响应 postMessage 回来 → [webcap] 进实时日志
    if (g_wfCap) {
        if (!g_wfCapHandler) g_wfCapHandler = [MFWebCapHandler new];
        @try { ((void(*)(id,SEL,id,id))objc_msgSend)(ucc, sel_registerName("addScriptMessageHandler:name:"), g_wfCapHandler, @"mfwebcap"); }
        @catch (__unused NSException *e) {}   // 重复 name 会抛, 忽略
    }
    Class US = objc_getClass("WKUserScript");
    if (!US) return;
    NSString *js = mfWFScript();
    id us = ((id(*)(id,SEL))objc_msgSend)((id)US, sel_registerName("alloc"));
    // initWithSource:(NSString*) injectionTime:(NSInteger 0=DocStart) forMainFrameOnly:(BOOL NO=含子frame)
    us = ((id(*)(id,SEL,id,NSInteger,BOOL))objc_msgSend)(us, sel_registerName("initWithSource:injectionTime:forMainFrameOnly:"), js, (NSInteger)0, (BOOL)NO);
    if (!us) return;
    ((void(*)(id,SEL,id))objc_msgSend)(ucc, sel_registerName("addUserScript:"), us);
    objc_setAssociatedObject(ucc, &kWFInjectedKey, @YES, OBJC_ASSOCIATION_RETAIN);
    g_wfInjected++;
    wbLog(@"[webforge] ★注入 #%ld: %lu B → webview(DocStart) cap=%d", g_wfInjected, (unsigned long)js.length, g_wfCap);
}

// swizzled -[WKWebView initWithFrame:configuration:] — 创建前往 config 注入
static id wf_initFrame(id self, SEL _cmd, CGRect frame, id cfg) {
    if (g_wfOn) { @try { mfWFInject(cfg); } @catch (__unused NSException *e) {} }
    return ((id(*)(id,SEL,CGRect,id))g_wfOrigInitFrame)(self, _cmd, frame, cfg);
}
// swizzled -[WKWebView initWithCoder:] — storyboard 路径, init 后取 configuration 注入
static id wf_initCoder(id self, SEL _cmd, id coder) {
    id r = ((id(*)(id,SEL,id))g_wfOrigInitCoder)(self, _cmd, coder);
    if (g_wfOn && r) { @try { id cfg = ((id(*)(id,SEL))objc_msgSend)(r, sel_registerName("configuration")); mfWFInject(cfg); } @catch (__unused NSException *e) {} }
    return r;
}

static void mfWFInstall(void) {
    if (g_wfOrigInitFrame || g_wfOrigInitCoder) return;   // 幂等
    Class WV = objc_getClass("WKWebView");
    if (!WV) { wbLog(@"[webforge] WKWebView 类缺失(app 无 WebView) — 注入引擎跳过"); return; }
    Method mF = class_getInstanceMethod(WV, sel_registerName("initWithFrame:configuration:"));
    if (mF) { g_wfOrigInitFrame = method_setImplementation(mF, (IMP)wf_initFrame); wbLog(@"[webforge] initWithFrame:configuration: swizzled"); }
    Method mC = class_getInstanceMethod(WV, sel_registerName("initWithCoder:"));
    if (mC) { g_wfOrigInitCoder = method_setImplementation(mC, (IMP)wf_initCoder); wbLog(@"[webforge] initWithCoder: swizzled"); }
}

void mfWebBridgeForgeEnable(void) {
    mfWFInstall();          // v2.58.195: 装 WKUserScript 注入引擎(fetch/XHR 响应改写)
    g_wfOn = YES;
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
    g_wfOn = NO;   // v2.58.195: 关注入引擎(swizzle 保留, g_wfOn 门控下不再注入)
    [[NSUserDefaults standardUserDefaults] setBool:NO forKey:@"mfWebBridgeForgeEnabled"];
    wbLog(@"[wbforge] OFF");
}
void mfWebBridgeForgeSwitchChanged(UISwitch *sw) {
    if (sw.on) { mfWebBridgeForgeEnable(); mfToast(@"🌐 WebForge 引擎已开 · 抓改一体 · 重启 app 生效"); }
    else { mfWebBridgeForgeDisable(); mfToast(@"⏹️ WebForge 引擎已关"); }
}
void mfWebBridgeForgeAutoStart(void) {
    if (![[NSUserDefaults standardUserDefaults] boolForKey:@"mfWebBridgeForgeEnabled"]) return;
    mfWebBridgeForgeEnable();
    wbLog(@"[wbforge] AutoStart ON");
}
// v2.58.195: 判型总闸判出服务端/WebView 桥型时调用 — 自动激活 WebForge(免用户手动开开关)。
//   幂等: 已开则只补装(mfWFInstall 内部有幂等门); 持久化, 下次冷启动 AutoStart 自动恢复。
//   门控铁律: 只在判型确证服务端/桥型时被调, 非该型 app 永不激活, 零影响其它 app。
void mfWebForgeAutoDispatch(void) {
    if (g_wfOn && g_wbOn) return;   // 已全激活
    mfWebBridgeForgeEnable();
    wbLog(@"[webforge] ⚡ 判型总闸自动派发: 服务端/WebView 桥型 → WebForge 已激活(抓改一体)");
}
long mfWebBridgeForgeHits(void) { return g_wbHits + g_wfInjected; }
BOOL mfWebBridgeForgeIsOn(void) { return g_wbOn || g_wfOn; }
