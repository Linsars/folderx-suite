// MFWebBridgeForge.m — WebView 采集器 + 规则注入执行器 (v2.58.196)
// 【定位】WebView / 服务端权益型 app 的本地解 —— NSURLProtocol(网络分析)只拦 app 原生
//   NSURLSession, 拦不到 WKWebView 网页内 JS 的 fetch/XHR(独立 Networking 进程)。本模块
//   在网页 JS 环境补上这一层, 与网络分析互补。
// 【职责边界(v2.58.196 重构, 用户铁令)】本模块 = 无脑执行器, 不含判型/生成:
//   · 采集器(mfWebCollectorInstall): 随网络捕获启动就跑, swizzle WKWebView init, 注入
//     只读 JS hook fetch/XHR → 响应解码回传 → 存 ring buffer(供 MFRecon 侦查读) + 并进
//     网络分析记录。不分析、不生成、不改包。
//   · 执行器(webinj@ 判定点驱动): 注入的同一段 JS 按"激活规则集"改包。规则集 = 判定点库里
//     on=YES 的 webinj@ 点位的 recipe(唯一事实源 = 判定点库, 本模块不自存规则)。
//   · 判型/生成规则 = MFRecon 的活(读 ring buffer 分析权益字段组 → 生成 webinj@ 点位)。
//   · 激活/持久化/删除/编辑 = 实验模拟页判定点卡片(与 sk2vfy@/hookinj@ 同一 UI)。
// 【机理】
//   腿A(桥消息): swizzle -[WKScriptMessage body] — postMessage 桥型(mailnow FlexCall)。
//   腿B(响应改写): swizzle -[WKWebView init...] → WKUserScript(DocStart)注入通用引擎,
//     hook fetch/XHR, 编码自适应(明文/base64反转/base64), 按 __MFR 规则改接口响应字段。
// 【app-agnostic】JS 骨架固定零 app 硬编码; app 特定的只有 recipe 规则数据(在判定点库)。
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "MFPanel.h"

#define wbLog(fmt, ...) mfLog((fmt), ##__VA_ARGS__)

// ============ 腿A: 桥消息改写(-[WKScriptMessage body]) ============
static BOOL g_wbOn = NO;
static long g_wbHits = 0;
static IMP  g_origBody = NULL;

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
static NSString *wbRewriteString(NSString *s, BOOL *changed) {
    if (![s isKindOfClass:[NSString class]] || s.length < 3) return s;
    BOOL maybe = NO;
    { const char *c = [[s lowercaseString] UTF8String];
      if (c) for (int i = 0; i < kWbEntKeyN; i++) if (strstr(c, kWbEntKeys[i])) { maybe = YES; break; } }
    if (!maybe) return s;
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
            id nv = wbRewriteObject(v, changed);
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
static id wb_body(id self, SEL _cmd) {
    id b = g_origBody ? ((id(*)(id,SEL))g_origBody)(self, _cmd) : nil;
    if (!g_wbOn || !b) return b;
    BOOL changed = NO;
    id nb = wbRewriteObject(b, &changed);
    if (changed) {
        g_wbHits++;
        NSString *desc = [b isKindOfClass:[NSString class]] ? b : [b description];
        if (desc.length > 100) desc = [desc substringToIndex:100];
        wbLog(@"[wbforge] ★桥权益改写 #%ld: %@ → 真值", g_wbHits, desc);
        return nb;
    }
    return b;
}

// ============ 采集 ring buffer(供 MFRecon 侦查读)============
static NSMutableArray *g_wcBuf = nil;         // 每条: @{@"u":url, @"e":编码, @"b":解码JSON}
static long g_wfCapN = 0;
#define WC_MAX 60
// MFRecon 侦查时读: 返回采集到的响应快照(url + 解码后 JSON body)
NSArray *mfWebCapBuffer(void) {
    @synchronized (g_wcBuf ?: [NSNull null]) { return g_wcBuf ? [g_wcBuf copy] : @[]; }
}

// ============ 执行器状态 ============
static BOOL g_wcInstalled = NO;               // WKWebView init swizzle 装了没
static IMP  g_wfOrigInitFrame = NULL;
static IMP  g_wfOrigInitCoder = NULL;
static char kWFInjectedKey;
static long g_wfInjected = 0;
static id   g_wfCapHandler = nil;

// 激活规则集 = 判定点库里 on=YES 的 webinj@ 点位 recipe(唯一事实源, 本模块不自存)。
// MFAppPatch 暴露 mfActiveWebinjRecipes() 返回 [{u:..,set:{..}}, ...]。
static NSString *mfWFActiveRulesJSON(void) {
    extern NSArray *mfActiveWebinjRecipes(void);
    NSArray *rules = mfActiveWebinjRecipes();
    if (![rules isKindOfClass:[NSArray class]]) rules = @[];
    NSData *d = [NSJSONSerialization dataWithJSONObject:rules options:0 error:nil];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : @"[]";
}

// 通用引擎 JS(固定, 零 app 硬编码): 采集(始终) + 按 __MFR 规则改包
// v2.58.197: ★修 fetch 头 bug(Rusku 对比实证): 重建 Response 必须删 content-length/
//   content-encoding/content-type —— 原头是加密体长度+gzip, 新 body 是重编码明文串, 头不删
//   → 客户端按旧 length 截断 / 按 gzip 解非 gzip → 响应损坏丢弃改包(=改了不生效根因)。
//   + 改包后经 mfwebcap 回传 {chg,k} → [webchg] 日志(验证改包真落地)。
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
    @"function post(o){if(!C)return;try{webkit.messageHandlers.mfwebcap.postMessage(JSON.stringify(o).slice(0,4000));}catch(e){}}"
    @"function app(u,j){var ks=[];for(var i=0;i<R.length;i++){var r=R[i];if((''+u).indexOf(r.u)<0)continue;if(r.set)for(var p in r.set){sp(j,p,r.set[p]);ks.push(p);}}return ks;}"
    @"function mkh(r){var h=new Headers();try{r.headers.forEach(function(v,k){var lk=k.toLowerCase();if(lk=='content-length'||lk=='content-encoding'||lk=='content-type')return;h.set(k,v);});}catch(e){}h.set('Content-Type','text/html;charset=utf-8');return h;}"
    @"function proc(u,t){var d;try{d=dec(t);}catch(e){d=null;}if(!d)return null;post({u:u,e:d.e,b:d.j});var ks=app(u,d.j);if(!ks.length)return null;post({chg:u,k:ks});try{return enc(d.j,d.e);}catch(e){return null;}}"
    @"try{if(window.fetch){var of=window.fetch.bind(window);window.fetch=function(){var a=arguments,u=typeof a[0]=='string'?a[0]:((a[0]&&a[0].url)||'');return of.apply(window,a).then(function(r){try{return r.clone().text().then(function(t){var n=proc(u,t);if(n==null)return r;return new Response(n,{status:r.status,statusText:r.statusText,headers:mkh(r)});}).catch(function(){return r;});}catch(e){return r;}});};}}catch(e){}"
    @"try{var NX=window.XMLHttpRequest;if(NX){var W=function(){var x=new NX(),u='';var no=x.open;x.open=function(m,url){u=''+url;return no.apply(x,arguments);};try{x.addEventListener('readystatechange',function(){try{if(x.readyState==4){var n=proc(u,x.responseText);if(n!=null){Object.defineProperty(x,'responseText',{configurable:true,get:function(){return n;}});Object.defineProperty(x,'response',{configurable:true,get:function(){return n;}});}}}catch(e){}},true);}catch(e){}return x;};W.prototype=NX.prototype;window.XMLHttpRequest=W;}}catch(e){}"
    @"})();";
}

// 完整自定义 JS 后门(webforge_<bid>.js / webforge.js) — 编码/逻辑特殊时完整接管
static NSString *mfWFScript(void) {
    NSString *dir = @"/var/jb/var/mobile/minisfix";
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    NSString *custom = [NSString stringWithContentsOfFile:[dir stringByAppendingPathComponent:[NSString stringWithFormat:@"webforge_%@.js", bid]] encoding:NSUTF8StringEncoding error:nil];
    if (!custom.length) custom = [NSString stringWithContentsOfFile:[dir stringByAppendingPathComponent:@"webforge.js"] encoding:NSUTF8StringEncoding error:nil];
    if (custom.length) { wbLog(@"[webforge] 用自定义 JS (%lu B)", (unsigned long)custom.length); return custom; }
    NSString *rules = mfWFActiveRulesJSON();
    NSString *header = [NSString stringWithFormat:@"window.__MFR=%@;window.__MFCAP=true;", rules];
    wbLog(@"[webforge] 引擎 header: 激活规则 %@", rules.length > 200 ? [rules substringToIndex:200] : rules);
    return [header stringByAppendingString:mfWFBuiltinJS()];
}

// ============ 采集回传 handler ============
@interface MFWebCapHandler : NSObject
@end
@implementation MFWebCapHandler
- (void)userContentController:(id)ucc didReceiveScriptMessage:(id)msg {
    @try {
        id b = ((id(*)(id,SEL))objc_msgSend)(msg, sel_registerName("body"));
        NSString *s = [b isKindOfClass:[NSString class]] ? (NSString *)b : [b description];
        NSData *jd = [s dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *env = jd ? [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil] : nil;
        if (![env isKindOfClass:[NSDictionary class]]) return;
        // v2.58.197: 改包后验证信封 {chg:url, k:[字段]} — 证明改包真落地(不再靠猜)
        if (env[@"chg"]) {
            wbLog(@"[webchg] ★改包生效 %@ 改字段: %@", env[@"chg"], [env[@"k"] componentsJoinedByString:@","]);
            return;
        }
        // 采集信封 {u,e,b}
        g_wfCapN++;
        NSString *disp = s.length > 1500 ? [s substringToIndex:1500] : s;
        wbLog(@"[webcap] #%ld %@", g_wfCapN, disp);   // ① 实时日志
        // ② 并进网络分析记录(与原生请求同列表)
        extern void mfNetAddWebCapRecord(NSString *url, NSString *enc, id bodyJSON);
        mfNetAddWebCapRecord(env[@"u"] ?: @"?", env[@"e"], env[@"b"]);
        // ③ 存 ring buffer(供 MFRecon 侦查读, 做权益字段组分析 → 生成 webinj@)
        @synchronized (g_wcBuf ?: [NSNull null]) {
            if (!g_wcBuf) g_wcBuf = [NSMutableArray new];
            if (g_wcBuf.count >= WC_MAX) [g_wcBuf removeObjectAtIndex:0];
            [g_wcBuf addObject:env];
        }
        // 本模块不 harvest/不生成规则(那是 MFRecon 侦查层职责)
    } @catch (__unused NSException *e) {}
}
@end

// 往 config 的 userContentController 注入采集+改包 JS + 采集桥
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
    if (!g_wfCapHandler) g_wfCapHandler = [MFWebCapHandler new];
    @try { ((void(*)(id,SEL,id,id))objc_msgSend)(ucc, sel_registerName("addScriptMessageHandler:name:"), g_wfCapHandler, @"mfwebcap"); }
    @catch (__unused NSException *e) {}
    Class US = objc_getClass("WKUserScript");
    if (!US) return;
    NSString *js = mfWFScript();
    id us = ((id(*)(id,SEL))objc_msgSend)((id)US, sel_registerName("alloc"));
    us = ((id(*)(id,SEL,id,NSInteger,BOOL))objc_msgSend)(us, sel_registerName("initWithSource:injectionTime:forMainFrameOnly:"), js, (NSInteger)0, (BOOL)NO);
    if (!us) return;
    ((void(*)(id,SEL,id))objc_msgSend)(ucc, sel_registerName("addUserScript:"), us);
    objc_setAssociatedObject(ucc, &kWFInjectedKey, @YES, OBJC_ASSOCIATION_RETAIN);
    g_wfInjected++;
    wbLog(@"[webforge] ★注入 #%ld: %lu B → webview(DocStart)", g_wfInjected, (unsigned long)js.length);
}
static id wf_initFrame(id self, SEL _cmd, CGRect frame, id cfg) {
    @try { mfWFInject(cfg); } @catch (__unused NSException *e) {}
    return ((id(*)(id,SEL,CGRect,id))g_wfOrigInitFrame)(self, _cmd, frame, cfg);
}
static id wf_initCoder(id self, SEL _cmd, id coder) {
    id r = ((id(*)(id,SEL,id))g_wfOrigInitCoder)(self, _cmd, coder);
    @try { id cfg = ((id(*)(id,SEL))objc_msgSend)(r, sel_registerName("configuration")); mfWFInject(cfg); } @catch (__unused NSException *e) {}
    return r;
}

// ============ 对外 API ============
// 采集器安装: swizzle WKWebView init(幂等) + 桥消息改写(腿A)。随网络捕获/判定点激活调用。
// 采集始终工作(注入 JS 恒 hook fetch/XHR 回传); 改包按激活规则集(空规则=纯采集)。
void mfWebCollectorInstall(void) {
    if (g_wcInstalled) return;
    Class WV = objc_getClass("WKWebView");
    if (!WV) { wbLog(@"[webforge] WKWebView 缺失(app 无 WebView) — 采集器跳过"); return; }
    Method mF = class_getInstanceMethod(WV, sel_registerName("initWithFrame:configuration:"));
    if (mF) { g_wfOrigInitFrame = method_setImplementation(mF, (IMP)wf_initFrame); }
    Method mC = class_getInstanceMethod(WV, sel_registerName("initWithCoder:"));
    if (mC) { g_wfOrigInitCoder = method_setImplementation(mC, (IMP)wf_initCoder); }
    // 腿A: 桥消息改写(仅当有激活的桥型 webinj@ 时才真改, 平时透传)
    Class WK = objc_getClass("WKScriptMessage");
    if (WK && !g_origBody) {
        Method m = class_getInstanceMethod(WK, @selector(body));
        if (m) { g_origBody = method_setImplementation(m, (IMP)wb_body); g_wbOn = YES; }
    }
    g_wcInstalled = YES;
    wbLog(@"[webforge] 采集器已装(WKWebView init swizzled) — 采集恒开, 改包按激活规则");
}

// webinj@ 判定点 ⚡ 激活时调用(单点/批量/冷启动重打共用): 确保采集器已装。
//   规则集从判定点库动态读(mfActiveWebinjRecipes), 无需在此传 recipe。
void mfWebForgeActivate(void) {
    mfWebCollectorInstall();
    wbLog(@"[webforge] ⚡ webinj@ 激活 — 采集器就位, 下次 webview 注入按激活规则改包(重启 app 生效)");
}

long mfWebForgeInjectCount(void) { return g_wfInjected; }
long mfWebForgeCapCount(void) { return g_wfCapN; }
