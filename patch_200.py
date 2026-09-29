#!/usr/bin/env python3
# 2.58.200 三改: L3死文案清零 + 腿A挂判定点门 + 判型采集器源收紧
import sys

EDITS = [
    # ============ MFRecon.m ============
    ("MFRecon.m",
     '    //   桥信号只用于: 判 serverSide 型 + 提供 L3 桥改写路线; 本地代码点照常入库作候选第二腿, 用户可试。',
     '    //   桥信号只用于: 判 serverSide 型 + 生成 webinj@bridge 桥改写点位(200: 腿A挂判定点门, 原恒开退役); 本地代码点照常入库作候选第二腿, 用户可试。'),
    ("MFRecon.m",
     '        mfLog(@"[f8v2] 运行时 WebView 桥权益在场(rt桥=1): 判服务端桥型+L3 改写路线, 但本地代码点仍入库作候选(不硬闸, 防误杀多链本地腿)");',
     '        mfLog(@"[f8v2] 运行时 WebView 桥权益在场(rt桥=1): 判服务端桥型+桥改写点位 webinj@bridge(⚡ 激活生效), 但本地代码点仍入库作候选(不硬闸, 防误杀多链本地腿)");'),
    ("MFRecon.m",
     '''static int mfReconGenWebinjPoints(void) {
    extern NSArray *mfWebCapBuffer(void);
    NSArray *buf = mfWebCapBuffer();
    if (![buf isKindOfClass:[NSArray class]] || !buf.count) {
        mfLog(@"[webinj-gen] 采集缓冲空(未浏览会员页?) — 无接口可分析, 0 点");
        return 0;
    }
    NSString *mainPath = [[NSBundle mainBundle] executablePath];
    NSString *img = mainPath ? [mainPath lastPathComponent] : @"main";''',
     '''// v2.58.200: 桥型证据(gRtWebBridge)也生成点位 — webinj@bridge。腿A(桥消息改写)从此只认
//   这个点位(⚡ 激活才改包), 不再随采集器恒开 — 196"删 L3 独立开关并入判定点体系"的落地补完。
static int mfReconGenWebinjPoints(BOOL bridgeEv) {
    extern NSArray *mfWebCapBuffer(void);
    NSString *mainPath = [[NSBundle mainBundle] executablePath];
    NSString *img = mainPath ? [mainPath lastPathComponent] : @"main";
    int n = 0;
    if (bridgeEv) {
        NSDictionary *bpt = @{
            @"img": img, @"sym": @"webinj@bridge", @"shape": @"webinj", @"kind": @"webforge",
            @"vmaddr": @0, @"slide": @0, @"score": @(90), @"on": @NO,
            @"note": @"WebView 桥消息权益改写(WKScriptMessage body: 权益键假→真, 通用键族)",
            @"recipe": @{ @"u": @"__bridge", @"bridge": @YES },
        };
        extern NSUInteger mfAppPatchEntDumpsMerge(NSArray *);
        mfAppPatchEntDumpsMerge(@[bpt]);
        n++;
        mfLog(@"[webinj-gen] ✅ 注册 webinj@bridge (桥消息权益改写, ⚡ 激活后生效)");
    }
    NSArray *buf = mfWebCapBuffer();
    if (![buf isKindOfClass:[NSArray class]] || !buf.count) {
        mfLog(@"[webinj-gen] 采集缓冲空(未浏览网页?) — 无接口可分析");
        return n;
    }'''),
    ("MFRecon.m",
     '''    int n = 0;
    for (NSString *u in byURL) {''',
     '''    for (NSString *u in byURL) {'''),
    ("MFRecon.m",
     'int nWebinj = mfReconGenWebinjPoints();',
     'int nWebinj = mfReconGenWebinjPoints(gRtWebBridge);'),
    ("MFRecon.m",
     '''    extern NSArray *mfWebCapBuffer(void);
    NSArray *gWebCap = mfWebCapBuffer();
    BOOL gWebApiCaptured = ([gWebCap isKindOfClass:[NSArray class]] && gWebCap.count > 0);
    if ((gRtWebBridge || gWebApiCaptured) && !cloud && !mach) serverSide = YES;''',
     '''    // v2.58.200 (dbg_186): "非空"收紧为"含权益字段组" — 非空会被纯流量记录满足(靶子 ring buffer
    //   里只有广告 SDK 配置 1 条、零权益字段也非空)。判型源必须是权益 API 证据, 不是"有流量"。
    extern NSArray *mfWebCapBuffer(void);
    NSArray *gWebCap = mfWebCapBuffer();
    BOOL gWebApiCaptured = NO;
    NSUInteger gWebCapEntN = 0;
    if ([gWebCap isKindOfClass:[NSArray class]]) {
        for (NSDictionary *mfcEnv in gWebCap) {
            if (![mfcEnv isKindOfClass:[NSDictionary class]]) continue;
            NSMutableDictionary *mfProbe = [NSMutableDictionary dictionary];
            mfWJHarvest(mfcEnv[@"b"], @"", mfProbe);   // 含权益字段才算 webview 权益证据
            if (mfProbe.count) { gWebCapEntN++; gWebApiCaptured = YES; }
        }
    }
    if ((gRtWebBridge || gWebApiCaptured) && !cloud && !mach) serverSide = YES;'''),
    ("MFRecon.m",
     '        //   fetch/XHR 型(啪啪搜)不打桥日志, 靠 ring buffer 非空识别; 桥型(mailnow)靠 gRtWebBridge。',
     '        //   fetch/XHR 型不打桥日志, 靠 ring buffer 含权益字段识别(200 收紧); 桥型靠 gRtWebBridge。'),
    ("MFRecon.m",
     '            [ev addObject:[NSString stringWithFormat:@"采集器实锤: 抓到 %lu 条网页 fetch/XHR API 响应(NSURLProtocol 抓不到的网页请求)", (unsigned long)gWebCap.count]];',
     '            [ev addObject:[NSString stringWithFormat:@"采集器实锤: 抓到 %lu 条网页 fetch/XHR API 响应, 其中 %lu 条含权益字段(NSURLProtocol 抓不到的网页请求)", (unsigned long)gWebCap.count, (unsigned long)gWebCapEntN]];'),
    # ============ MFAppPatch.m ============
    ("MFAppPatch.m",
     '''        if ([rc[@"ls"] isKindOfClass:[NSDictionary class]] && [rc[@"ls"] count]) r[@"ls"] = rc[@"ls"];
        if (r[@"set"] || r[@"req"] || r[@"ls"]) [out addObject:r];''',
     '''        if ([rc[@"ls"] isKindOfClass:[NSDictionary class]] && [rc[@"ls"] count]) r[@"ls"] = rc[@"ls"];
        if ([rc[@"bridge"] boolValue]) r[@"bridge"] = @YES;   // v2.58.200: 腿A 桥改写点位(webinj@bridge)
        if (r[@"set"] || r[@"req"] || r[@"ls"] || r[@"bridge"]) [out addObject:r];'''),
    # ============ MFWebBridgeForge.m ============
    ("MFWebBridgeForge.m",
     '''static id wb_body(id self, SEL _cmd) {
    id b = g_origBody ? ((id(*)(id,SEL))g_origBody)(self, _cmd) : nil;
    if (!g_wbOn || !b) return b;''',
     '''// v2.58.200: 腿A 门 — 桥改写不再随采集器恒开(196"删 L3 并入判定点"落地补完, dbg_186 纠)。
//   只在判定点库存在激活的 webinj@bridge 点位(⚡)时改写; 动态读, 激活/失活即时生效。
static BOOL mfWFbridgeActive(void) {
    extern NSArray *mfActiveWebinjRecipes(void);
    for (NSDictionary *r in mfActiveWebinjRecipes())
        if ([r[@"bridge"] boolValue]) return YES;
    return NO;
}
static id wb_body(id self, SEL _cmd) {
    id b = g_origBody ? ((id(*)(id,SEL))g_origBody)(self, _cmd) : nil;
    if (!g_wbOn || !b || !mfWFbridgeActive()) return b;'''),
    ("MFWebBridgeForge.m",
     '//   腿A(桥消息): swizzle -[WKScriptMessage body] — postMessage 桥型(mailnow FlexCall)。',
     '//   腿A(桥消息): swizzle -[WKScriptMessage body] — postMessage 桥型。200: 门=webinj@bridge 点位激活, 不再恒开。'),
    ("MFWebBridgeForge.m",
     '''    NSArray *rules = mfActiveWebinjRecipes();
    if (![rules isKindOfClass:[NSArray class]]) rules = @[];''',
     '''    NSArray *rules = mfActiveWebinjRecipes();
    if (![rules isKindOfClass:[NSArray class]]) rules = @[];
    // v2.58.200: 桥点位(bridge=1)不进 URL 规则表 — 它不是接口改写规则, 腿A在 wb_body 消费。
    NSMutableArray *mfcUrlRules = [NSMutableArray array];
    for (NSDictionary *r in rules) if (![r[@"bridge"] boolValue]) [mfcUrlRules addObject:r];
    rules = mfcUrlRules;'''),
]

applied = {}
for path, old, new in EDITS:
    src = open(path, encoding="utf-8").read()
    cnt = src.count(old)
    if cnt != 1:
        print(f"FAIL {path}: pattern count={cnt}\n---\n{old[:180]}")
        sys.exit(1)
    open(path, "w", encoding="utf-8").write(src.replace(old, new, 1))
    applied[path] = applied.get(path, 0) + 1
print("OK", applied)
