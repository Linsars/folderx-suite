#!/usr/bin/env python3
# 2.58.201: ① 页面样本采集(DocEnd outerHTML → Documents/MinisFix/page_*.html, 补主文档抓包盲区)
#           ② 生成器 merge 被墓碑拒绝仍谎报"✅注册"修复
import sys

EDITS = [
    # ===== MFWebBridgeForge.m =====
    ("MFWebBridgeForge.m",
     '''static long g_wfInjected = 0;
static id   g_wfCapHandler = nil;''',
     '''static long g_wfInjected = 0;
static id   g_wfCapHandler = nil;
static long g_wfPgN = 0;               // v2.58.201: 页面样本计数(page_*.html 落盘)
static NSMutableSet *g_wfPgSeen = nil;  // v2.58.201: 本进程已写页去重'''),
    ("MFWebBridgeForge.m",
     '''//     网络分析记录。不分析、不生成、不改包。''',
     '''//     网络分析记录。不分析、不生成、不改包。
//   · 页面样本(v2.58.201): DocEnd 引擎回传 document.outerHTML → Documents/MinisFix/page_*.html
//     — 主文档是抓包盲区(NSURLProtocol/fetch/XHR 三层都看不见), 判定常烘进 HTML(config_domain 案),
//     落盘给实验层直接定位门, 不再依赖用户 Surge 肉眼翻。'''),
    ("MFWebBridgeForge.m",
     '''    @"function post(o){if(!C)return;try{webkit.messageHandlers.mfwebcap.postMessage(JSON.stringify(o).slice(0,4000));}catch(e){}}"''',
     '''    @"function post(o){if(!C)return;try{webkit.messageHandlers.mfwebcap.postMessage(JSON.stringify(o).slice(0,4000));}catch(e){}}"
    @"function postp(o){if(!C)return;try{webkit.messageHandlers.mfwebcap.postMessage(JSON.stringify(o).slice(0,1000000));}catch(e){}}"
    @"try{document.addEventListener('DOMContentLoaded',function(){try{var h='';try{h=document.documentElement.outerHTML;}catch(e){}if(h&&h.length>200)postp({pg:location.href,h:h});}catch(e){}},{once:true});}catch(e){}"'''),
    ("MFWebBridgeForge.m",
     '''        if (env[@"rq"]) {
            wbLog(@"[webrq] ★请求改写生效 %@ 抹参数: %@", env[@"rq"], [env[@"k"] componentsJoinedByString:@","]);
            return;
        }''',
     '''        if (env[@"rq"]) {
            wbLog(@"[webrq] ★请求改写生效 %@ 抹参数: %@", env[@"rq"], [env[@"k"] componentsJoinedByString:@","]);
            return;
        }
        // v2.58.201: 页面样本信封 {pg:url, h:html} — 主文档 HTML 落盘(抓包盲区补洞)
        if (env[@"pg"]) {
            NSString *html = [env[@"h"] isKindOfClass:[NSString class]] ? env[@"h"] : nil;
            NSString *url = [env[@"pg"] isKindOfClass:[NSString class]] ? env[@"pg"] : @"?";
            if (html.length > 200) {
                if (!g_wfPgSeen) g_wfPgSeen = [NSMutableSet set];
                // 文件名 = URL 末段清洗(去 query/防路径穿越/非法字符 → '_'), 每进程每页首载写一次
                NSString *name = nil;
                @try { NSURL *pu = [NSURL URLWithString:url]; name = pu.path.lastPathComponent; } @catch (__unused NSException *e) {}
                if (!name.length) name = @"page.html";
                NSMutableString *sb = [NSMutableString string];
                for (NSUInteger i = 0; i < name.length && i < 60; i++) {
                    unichar c = [name characterAtIndex:i];
                    BOOL okc = (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c=='_';
                    [sb appendFormat:@"%C", okc ? c : '_'];
                }
                name = sb.length >= 3 ? [sb copy] : @"page.html";
                if ([g_wfPgSeen containsObject:name]) return;
                [g_wfPgSeen addObject:name];
                @try {
                    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MinisFix"];
                    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
                    g_wfPgN++;
                    NSString *path = [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"page_%03ld_%@", (long)g_wfPgN, name]];
                    NSError *werr = nil;
                    if ([html writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&werr])
                        wbLog(@"[webcap] ★页面样本 #%ld %luB %@ → Documents/MinisFix/%@", (long)g_wfPgN, (unsigned long)html.length, url, path.lastPathComponent);
                    else wbLog(@"[webcap] ✗页面样本写盘失败 %@", werr.localizedDescription ?: @"-");
                } @catch (__unused NSException *e) {}
            }
            return;
        }'''),
    # ===== MFRecon.m =====
    ("MFRecon.m",
     '''        extern NSUInteger mfAppPatchEntDumpsMerge(NSArray *);
        mfAppPatchEntDumpsMerge(@[bpt]);
        n++;
        mfLog(@"[webinj-gen] ✅ 注册 webinj@bridge (桥消息权益改写, ⚡ 激活后生效)");''',
     '''        extern NSUInteger mfAppPatchEntDumpsMerge(NSArray *);
        // v2.58.201: 看 merge 实际返回 — 被墓碑拒绝时旧版仍打"✅注册"= 虚报(dbg 真机 ⚰+✅ 连打)
        if (mfAppPatchEntDumpsMerge(@[bpt])) {
            n++;
            mfLog(@"[webinj-gen] ✅ 注册 webinj@bridge (桥消息权益改写, ⚡ 激活后生效)");
        } else {
            mfLog(@"[webinj-gen] ⚰ webinj@bridge 被墓碑挡回(已删不复活) — ♻ 清墓碑后重扫入库");
        }'''),
    ("MFRecon.m",
     '''        extern NSUInteger mfAppPatchEntDumpsMerge(NSArray *);
        mfAppPatchEntDumpsMerge(@[pt]);
        n++;
        mfLog(@"[webinj-gen] ✅ 注册 %@ (改 %lu 字段: %@%@)", sym, (unsigned long)set.count, [set.allKeys componentsJoinedByString:@","],''',
     '''        extern NSUInteger mfAppPatchEntDumpsMerge(NSArray *);
        if (!mfAppPatchEntDumpsMerge(@[pt])) {   // v2.58.201: 墓碑拒绝不虚报
            mfLog(@"[webinj-gen] ⚰ %@ 被墓碑挡回(已删不复活) — ♻ 清墓碑后重扫入库", sym);
            continue;
        }
        n++;
        mfLog(@"[webinj-gen] ✅ 注册 %@ (改 %lu 字段: %@%@)", sym, (unsigned long)set.count, [set.allKeys componentsJoinedByString:@","],'''),
]

applied = {}
for path, old, new in EDITS:
    src = open(path, encoding="utf-8").read()
    cnt = src.count(old)
    if cnt != 1:
        print(f"FAIL {path}: pattern count={cnt}\n---\n{old[:200]}")
        sys.exit(1)
    open(path, "w", encoding="utf-8").write(src.replace(old, new, 1))
    applied[path] = applied.get(path, 0) + 1
print("OK", applied)
