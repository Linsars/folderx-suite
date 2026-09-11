// MFRecon.m — 内购模式一次性侦查(扫描时点指纹, 零 hook 零常驻, 纯读)
// 判据 v2(2026-09-05 用户 Reflix 实测纠偏):
//   云验证类   — RC/SW/Adapty 等订阅 SDK 品牌串/域名串/RC 缓存 → MFSubInject mock 直达
//   mach 协议类 — ★ 判据收紧: 进程异常端口表里存在【独立 BREAKPOINT 条目】(mask==0x40
//               且 beh==MACH_EXCEPTION_CODES|EXCEPTION_STATE 且 flv==ARM_THREAD_STATE64)
//               = 伴侣 dylib 注册的本地许可服务器(2.38.4 实测指纹 mask=0x40 beh=-2147483646 flv=6)
//   ✗ 已废弃 brk 大立即数判据 — 2.39.7 旧注释"app 查询=brk #0x965…"系误读, 终案实锤陷阱为
//     vendor 运行时写入的常规 brk, 静态二进制无此指纹(用户实测 29639 brk 全编译器常规)
//   ✗ 系统级 crash handler(mask 混合 0x104e/IDENTITY/flv5)不再误标 — Reflix 型必须是独立条目

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <string.h>
#import "MFPanel.h"

extern CGFloat g_mfCardW;
extern UIViewController *g_mfPanelRootVC;
extern mach_port_t g_mitmMyPort;   // 自家 EXCPROBE 端口(0=未武装)

// ---- 品牌串 → SDK 名映射(判定报告用具体名字, 不打抽象标签) ----
static NSArray *mfRecCloudBrands(void) {
    return @[
        @{@"pats": @[@"api.revenuecat.com", @"rc-backup", @"revenuecat", @"RevenueCat", @"com.revenuecat"], @"name": @"RevenueCat"},
        @{@"pats": @[@"superwall", @"Superwall"], @"name": @"Superwall"},
        @{@"pats": @[@"adapty", @"Adapty"], @"name": @"Adapty"},
        @{@"pats": @[@"qonversion", @"Qonversion"], @"name": @"Qonversion"},
        @{@"pats": @[@"apphud", @"Apphud"], @"name": @"Apphud"},
        @{@"pats": @[@"purchasely", @"Purchasely"], @"name": @"Purchasely"},
        @{@"pats": @[@"Glassfy"], @"name": @"Glassfy"},
    ];
}

static const uint8_t *mfRecFind(const uint8_t *hay, size_t hn, const char *ndl) {
    size_t nl = strlen(ndl);
    if (!hay || !nl || hn < nl) return NULL;
    return (const uint8_t *)memmem(hay, hn, ndl, nl);
}

// v2.58.6: 命中点是否落在 SPM 依赖清单 URL 里("https://github.com/<org>/<repo>")
// 判据: 从命中点向左回退到 C 串头, 串以 "https://github.com/" 开头即 SPM URL(工具库依赖, 非订阅 SDK)
static BOOL mfRecIsSPMURL(const uint8_t *base, const uint8_t *hit) {
    if (!base || hit < base) return NO;
    size_t back = 0, maxb = 128;
    while (hit - back > base && back < maxb && hit[-back - 1] != 0) back++;
    const uint8_t *strStart = hit - back;
    static const char *kGH = "https://github.com/";
    size_t gl = strlen(kGH);
    // 串头在 base 内且完整出现前缀
    return (size_t)(hit - back - base) >= gl && !memcmp(strStart, kGH, gl);
}

NSDictionary *mfReconFingerprint(void) {
    NSMutableArray *lines = [NSMutableArray array];
    NSMutableSet *cloudBrands = [NSMutableSet set];
    BOOL mach = NO;
    NSString *skType = @"未知", *validator = @"无收据验证特征";

    // ---- F1 二进制品牌串/域名串 ----
    NSString *exe = [[NSBundle mainBundle] executablePath];
    NSData *d = exe ? [NSData dataWithContentsOfFile:exe options:NSDataReadingMappedIfSafe error:NULL] : nil;
    const uint8_t *p = d.bytes;
    NSUInteger n = d.length;
    if (n > 320u * 1024 * 1024) { n = 320u * 1024 * 1024; [lines addObject:@"(二进制超 320MB, 指纹只扫前段)"]; }
    unsigned binHits = 0;
    for (NSDictionary *b in mfRecCloudBrands()) {
        BOOL brandHit = NO, spmOnly = NO;
        for (NSString *pat in b[@"pats"]) {
            // v2.58.6: 逐命中点检查 — SPM 依赖清单 URL(github.com/<org>/<repo>) 是误报大户:
            //   Scripting 案: superwall 小写串只出现在 "https://github.com/superwall/iOS-Backports"
            //   (工具库依赖, 非订阅 SDK), 真特征 SuperwallKit/api.superwall.com 全 0。
            //   策略: 命中点所在 C 串若以 https://github.com/ 开头 → 剔除该命中; 全部命中均 SPM 才判负。
            const uint8_t *cand = p;
            size_t rem = n;
            const char *pc = pat.UTF8String;
            while ((cand = mfRecFind(cand, rem, pc)) != NULL) {
                if (!mfRecIsSPMURL(p, cand)) { brandHit = YES; break; }
                spmOnly = YES;
                size_t adv = strlen(pc);
                cand += adv; rem = n - (size_t)(cand - p);
            }
            if (brandHit) break;
        }
        if (brandHit) {
            [cloudBrands addObject:b[@"name"]];
            binHits++;
            if (binHits <= 6) [lines addObject:[NSString stringWithFormat:@"二进制含订阅 SDK 串: %@ → %@", b[@"pats"][0], b[@"name"]]];
        } else if (spmOnly) {
            [lines addObject:[NSString stringWithFormat:@"剔除 %@ 串命中: 仅存在于 SPM 依赖清单 URL(github.com/…) — 工具库依赖, 非订阅 SDK", b[@"name"]]];
        }
    }
    if (binHits) [lines addObject:@"（二进制串 = 静态指纹, 不受任何开关影响 — 判定以此为准）"];

    // ---- F2 RC 缓存(云响应已到过本机) ----
    if ([[NSUserDefaults standardUserDefaults] objectForKey:@"com.revenuecat.userdefaults.productEntitlementMapping"]) {
        [cloudBrands addObject:@"RevenueCat"];
        BOOL inj = [[NSUserDefaults standardUserDefaults] boolForKey:@"mfSubInjectEnabled"];
        [lines addObject:inj ?
            @"RC 缓存在场（⚠ 订阅注入开启中, 此缓存可能是 mock 伪造响应写入的 — 弱证据）" :
            @"RC 缓存 productEntitlementMapping 在场"];
    }

    // ---- F1.5 Xray 采集残留(CompatPatcher 观察机若在本 app 采集过标本, 其授权形态可直接引用) ----
    {
        // v2.53.5: 侦查卡↔Xray 联动——读沙盒 mfcompat_xray.log 的 SUMMARY 行
        // mach=1 说明有本地许可服务器在场(Reflix/ScriptingPass 型); vmprot=1 说明有内联补丁动作
        NSString *home = NSHomeDirectory();
        NSString *xp = [home stringByAppendingPathComponent:@"Documents/mfcompat_xray.log"];
        NSString *xd = [NSString stringWithContentsOfFile:xp encoding:NSUTF8StringEncoding error:nil];
        if (xd.length) {
            BOOL viaRecon = [xd containsString:@"recon session"];
            // v2.55: 观察模块独立后, "兼容列表会话"文案过时——统一为"标本观察"(可能来自观察列表或兼容列表, 以观察模块为准)
            NSRange sr = [xd rangeOfString:@"SUMMARY cnt:" options:NSBackwardsSearch];
            if (sr.location != NSNotFound) {
                NSString *summ = [xd substringFromIndex:sr.location];
                [lines addObject:[NSString stringWithFormat:@"Xray 标本观察在场(%@): %@",
                    viaRecon ? @"侦查会话" : @"观察模块",
                    [[summ componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]] firstObject] ?: summ]];
                if ([summ containsString:@"mach=1"]) {
                    mach = YES;   // 许可服务器已实测上线——mach 协议型直接实锤(比端口推断强)
                    [lines addObject:@"Xray 实测: MACH_MSG_SERVER 已上线 → 本地许可服务器(mach 协议型)实锤"];
                }
                if ([summ containsString:@"vmprot="] && ![summ containsString:@"vmprot=0"])
                    [lines addObject:@"Xray 实测: vm_protect 被调用 → 内联补丁动作在场"];
            }
        }
    }

    // ---- F3 EXCPORTS 实况 — mach 类唯一判据(独立 BREAKPOINT 条目才算) ----
    {
        exception_mask_t masks[32]; mach_msg_type_number_t cnt = 32;
        mach_port_t ports[32]; exception_behavior_t behs[32]; thread_state_flavor_t flvs[32];
        kern_return_t kr = task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, masks, &cnt, ports, behs, flvs);
        if (kr != KERN_SUCCESS) {
            [lines addObject:[NSString stringWithFormat:@"EXCPORTS 读取失败 kr=%d", kr]];
        } else {
            BOOL found = NO;
            for (mach_msg_type_number_t i = 0; i < cnt; i++) {
                if (ports[i] == MACH_PORT_NULL) continue;
                found = YES;
                // Reflix 型强指纹: 独立 BREAKPOINT 条目 + MACH_EXCEPTION_CODES|EXCEPTION_STATE + ARM_THREAD_STATE64
                if (g_mitmMyPort != MACH_PORT_NULL && ports[i] == g_mitmMyPort) {
                    [lines addObject:@"EXCPORTS: 自家 EXCPROBE 端口(本插件侦查系统自身), 已剔除"];
                    continue;
                }
                if (masks[i] == EXC_MASK_BREAKPOINT && behs[i] == (MACH_EXCEPTION_CODES | EXCEPTION_STATE) && flvs[i] == 6) {
                    mach = YES;
                    [lines addObject:[NSString stringWithFormat:@"EXCPORTS[%u] 独立 BREAKPOINT 条目(MACH|STATE flv=6) → 本地许可服务器注册（mach 协议型内购特征）", (unsigned)i]];
                } else if (masks[i] & EXC_MASK_BREAKPOINT) {
                    [lines addObject:[NSString stringWithFormat:@"EXCPORTS[%u] mask=0x%x beh=%#x flv=%d → 系统级注册（crash handler, 每个进程都有, 与内购无关）", (unsigned)i, masks[i], behs[i], flvs[i]]];
                } else {
                    [lines addObject:[NSString stringWithFormat:@"EXCPORTS[%u] mask=0x%x beh=%#x flv=%d", (unsigned)i, masks[i], behs[i], flvs[i]]];
                }
            }
            if (!found) [lines addObject:@"EXCPORTS: 全空(无异常端口注册者)"];
        }
        // v2.58 定位修正(用户判定): EXCPORTS=检测"别家 mach 许可服务器"的观察判据(样本/Reflix 型),
        //   不是本插件 patch 流程的一环 — 只在 mach 命中时作为旁证输出, 不再当主判定展示。
    }

    // ---- F4 网络捕获域命中(自家探针流量剔除 — mfprobe offerings 是我们发的, 算自证) ----
    {
        NSArray *recs = mfCapturedRecordsSnapshot();
        unsigned hits = 0, selfHits = 0;
        NSMutableSet *seenUrl = [NSMutableSet set];
        for (MFNetRecord *r in recs) {
            NSString *u = r.url;
            if (!u.length) continue;
            if ([u containsString:@"mfprobe"]) { selfHits++; continue; }
            if ([seenUrl containsObject:u]) continue;   // 同 URL 去重
            [seenUrl addObject:u];
            NSString *lu = u.lowercaseString;
            for (NSDictionary *b in mfRecCloudBrands()) {
                for (NSString *pat in b[@"pats"]) {
                    if ([lu containsString:pat.lowercaseString]) {
                        hits++;
                        [cloudBrands addObject:b[@"name"]];
                        if (hits <= 3) [lines addObject:[NSString stringWithFormat:@"网络捕获命中: %@", u]];
                    }
                }
            }
        }
        if (selfHits) [lines addObject:[NSString stringWithFormat:@"网络捕获含自家探针流量 %u 条(mfprobe uid), 已剔除", selfHits]];
        if (hits > 3) [lines addObject:[NSString stringWithFormat:@"…网络捕获共 %u 条 App 自身云验证域请求", hits]];
        if (hits) [lines addObject:@"（网络捕获为辅助证据: 受捕获/注入开关影响, 判定以二进制静态指纹为准）"];
        if (!hits) [lines addObject:[NSString stringWithFormat:@"网络捕获 %lu 条记录, 无 App 云验证域(未开捕获或纯本地)", (unsigned long)recs.count]];
    }

    // ---- F6 SK 形态/本地校验策略(纯 SK 型的攻击层推荐依据) ----
    {
        NSMutableArray *scanBlobs = [NSMutableArray array];
        if (d.length) [scanBlobs addObject:d];   // 主二进制(p/n 可能截断, 用原 d)
        {
            // v2.58.5: 框架扫描改内存直读(__objc_methname + strtab) — v2.58.4 磁盘整文件 mmap 两条死路:
            //   ① Python 型 app(Scripting) 框架数百个(stdlib 全独立打包), 6-blob 配额被 stdlib 链占满,
            //      ScriptingKit 进不了扫描集 → SK 形态永远"未知"(实测设备日志实锤: F8 同刻已命中 ScriptingKit)
            //   ② 115MB 大文件磁盘 mmap 在部分环境返回 nil。
            //   特征串实际住处: SK1 selector 在 __TEXT.__objc_methname; SK2 Swift 符号/C import 在
            //   __LINKEDIT strtab — 两区每框架共几十 KB, 全量扫无配额; 内存地址算法与 F8 符号扫描同源(已实证)。
            uint32_t ic = _dyld_image_count();
            NSUInteger blobBytes = 0;
            for (uint32_t i = 0; i < ic && blobBytes < 96u * 1024 * 1024; i++) {
                const char *nmI = _dyld_get_image_name(i);
                if (!nmI) continue;
                NSString *full = [NSString stringWithUTF8String:nmI];
                if (![full containsString:@".app/Frameworks/"]) continue;
                const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
                if (!h || h->magic != MH_MAGIC_64) continue;
                intptr_t slide = _dyld_get_image_vmaddr_slide(i);
                const struct load_command *lc = (const struct load_command *)((const uint8_t *)h + sizeof(struct mach_header_64));
                int64_t lDelta = 0; uint32_t strsize = 0;
                for (uint32_t c = 0; c < h->ncmds; c++, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
                    if (lc->cmd == LC_SEGMENT_64) {
                        const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
                        if (!strcmp(sg->segname, "__LINKEDIT")) lDelta = (int64_t)sg->vmaddr - (int64_t)sg->fileoff;
                        else if (!strcmp(sg->segname, "__TEXT")) {
                            const struct section_64 *sects = (const struct section_64 *)((const uint8_t *)sg + sizeof(struct segment_command_64));
                            for (uint32_t s = 0; s < sg->nsects; s++) {
                                if (!strcmp(sects[s].sectname, "__objc_methname") && sects[s].size) {
                                    [scanBlobs addObject:[NSData dataWithBytes:(const void *)(uintptr_t)(sects[s].addr + (uint64_t)slide) length:(NSUInteger)sects[s].size]];
                                    blobBytes += sects[s].size;
                                }
                            }
                        }
                    } else if (lc->cmd == LC_SYMTAB) {
                        strsize = ((const struct symtab_command *)lc)->strsize;
                        if (strsize) [scanBlobs addObject:[NSData dataWithBytes:(const void *)((const uint8_t *)h + ((const struct symtab_command *)lc)->stroff + lDelta) length:strsize]];
                        blobBytes += strsize;
                    }
                }
            }
        }
        // runtime 类扫描(主二进制): 收据验证库指纹
        NSMutableArray *libHits = [NSMutableArray array];
        const char **clsNames = NULL;
        unsigned int clsCnt = 0;
        NSString *imgName = exe.lastPathComponent ?: @"";
        if (imgName.length) clsNames = objc_copyClassNamesForImage(imgName.UTF8String, &clsCnt);
        for (unsigned int i = 0; i < clsCnt; i++) {
            NSString *cn = [NSString stringWithUTF8String:clsNames[i]];
            if ([cn hasPrefix:@"InAppReceipt"] || [cn hasPrefix:@"ASN1"] || [cn hasPrefix:@"PKCS7"]) {
                if (![libHits containsObject:@"TPInAppReceipt"]) [libHits addObject:@"TPInAppReceipt"];
            } else if ([cn hasPrefix:@"SwiftyStoreKit"]) {
                if (![libHits containsObject:@"SwiftyStoreKit"]) [libHits addObject:@"SwiftyStoreKit"];
            } else if ([cn hasPrefix:@"RMStore"]) {
                if (![libHits containsObject:@"RMStore"]) [libHits addObject:@"RMStore"];
            }
        }
        free(clsNames);
        // 二进制串: SK1 selector(__objc_methname 里必留) / SK2 / CMS-OpenSSL 验签 import
        // v2.58: 扫描源 = 主二进制 + app 框架(scanBlobs) — SK2 特征常在自带框架里
        BOOL sk1 = NO, sk2 = NO, cms = NO;
        for (NSData *blob in scanBlobs) {
            const uint8_t *bp = blob.bytes; NSUInteger bn = blob.length;
            if (!sk1 && (mfRecFind(bp, bn, "addPayment:") || mfRecFind(bp, bn, "updatedTransactions:") ||
                         mfRecFind(bp, bn, "restoreCompletedTransactions"))) sk1 = YES;
            if (!sk2 && (mfRecFind(bp, bn, "currentEntitlements") || mfRecFind(bp, bn, "AppTransaction"))) sk2 = YES;
            if (!cms && (mfRecFind(bp, bn, "CMSDecoder") || mfRecFind(bp, bn, "d2i_PKCS7") || mfRecFind(bp, bn, "EVP_VerifyFinal"))) cms = YES;
            if (sk1 && sk2 && cms) break;
        }
        if (sk1 && sk2) skType = @"SK1+SK2 混合";
        else if (sk2) skType = @"SK2(JWS)";
        else if (sk1) skType = @"SK1(队列)";
        if (libHits.count) validator = [libHits componentsJoinedByString:@"/"];
        else if (cms) validator = @"自研 CMS/OpenSSL 验签";
        [lines addObject:[NSString stringWithFormat:@"SK 形态: %@ · 本地校验策略: %@", skType, validator]];
    }

    // ---- F8 entitlement 判定点位扫描(v2.57 链B: 扫描→定位, 产出可 patch 数据) ----
    // 对已加载的全部非系统框架(dylib, 非主程序)做符号表扫描, 找权益判定函数:
    //   Swift: *ProAccess*/*Entitlement*/*hasPro*/*hasValid*Token* 类的 Sb 返回值方法
    // 产出: {img, sym, vmaddr} 列表 — 供实验模拟页 AppPatch 引擎 swifttext 规则直接消费
    NSMutableArray *entFuncs = [NSMutableArray array];
    {
        uint32_t ic = _dyld_image_count();
        for (uint32_t i = 0; i < ic && entFuncs.count < 24; i++) {
            const char *n = _dyld_get_image_name(i);
            if (!n) continue;
            NSString *full = [NSString stringWithUTF8String:n];
            // 只扫 app 自带框架(Containers/Bundle 路径), 排除系统库噪音
            if (![full containsString:@".app/Frameworks/"]) continue;
            const struct mach_header *mh = _dyld_get_image_header(i);
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            // 符号表扫描: entitlement 判定模式
            const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
            if (!h || h->magic != MH_MAGIC_64) continue;
            const struct load_command *lc = (const struct load_command *)((const uint8_t *)h + sizeof(struct mach_header_64));
            uint32_t symoff = 0, nsyms = 0, stroff = 0; int64_t lDelta = 0;
            for (uint32_t c = 0; c < h->ncmds; c++, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
                if (lc->cmd == LC_SYMTAB) { const struct symtab_command *st = (const struct symtab_command *)lc; symoff = st->symoff; nsyms = st->nsyms; stroff = st->stroff; }
                else if (lc->cmd == LC_SEGMENT_64) { const struct segment_command_64 *sg = (const struct segment_command_64 *)lc; if (!strcmp(sg->segname, "__LINKEDIT")) lDelta = (int64_t)sg->vmaddr - (int64_t)sg->fileoff; }
            }
            if (!nsyms || !symoff) continue;
            const struct nlist_64 *syms = (const struct nlist_64 *)((const uint8_t *)h + symoff + lDelta);
            const char *strtab = (const char *)((const uint8_t *)h + stroff + lDelta);
            static NSArray *kEntPats; static dispatch_once_t o;
            dispatch_once(&o, ^{ kEntPats = @[@"ProAccessGuard", @"EntitlementOracle", @"hasValidD5Token",
                                              @"03hascD03now", @"hasProAccess"]; });
            unsigned imgHits = 0;
            for (uint32_t k = 0; k < nsyms && imgHits < 12; k++) {
                if (!(syms[k].n_type & N_SECT) || !syms[k].n_value) continue;
                const char *nm = strtab + syms[k].n_un.n_strx;
                if (!nm || !(nm[0] == '_' && nm[1] == '$')) continue;   // Swift mangled only
                // v2.57.1 正向过滤(只收真判定函数): Sb(Bool)返回 + tF(函数)/vg(getter)结尾。
                //   首版 8 个配额被 refreshStoreD0 闭包 thunk(yyYacfU_TATQ0_)占满, hasValidToken 没进表。
                size_t nl = strlen(nm);
                if (nl < 8) continue;
                BOOL endF = !strcmp(nm + nl - 2, "tF");
                BOOL endG = !strcmp(nm + nl - 2, "vg");
                if (!endF && !endG) continue;          // thunk(TQ0_/TA/yyYacfU)/async(tYaF)/metadata 全排除
                if (!strstr(nm, "Sb")) continue;        // 非 Bool 返回不打
                // v2.57.1: 返回类型是 y(void)开头的多参函数不打 — "ySb_S2b"(refreshFromPurchaseState)
                //   含 "Sb" 字样但是参数不是返回值, 打恒真会破坏正常购买流程
                if (endF && strstr(nm, "ySb")) continue;
                for (NSString *pat in kEntPats) {
                    if (strstr(nm, pat.UTF8String)) {
                        // v2.58.6: 同名符号 local/global 双 nlist 条目去重(否则计数翻倍, 与 merge 端 img+sym 去重口径不一致)
                        BOOL dupSym = NO;
                        for (NSDictionary *e in entFuncs)
                            if ([e[@"img"] isEqualToString:full.lastPathComponent] && [e[@"sym"] isEqualToString:[NSString stringWithUTF8String:nm]]) { dupSym = YES; break; }
                        if (dupSym) break;
                        [entFuncs addObject:@{
                            @"img": full.lastPathComponent,
                            @"sym": [NSString stringWithUTF8String:nm],
                            @"vmaddr": @((unsigned long)syms[k].n_value),
                            @"slide": @((long)slide),
                        }];
                        imgHits++;
                        break;
                    }
                }
            }
        }
        // v2.58 接线: 侦查→实验模拟页数据通道 — 扫到的点位直接合并进 mfEntDumps_<bid>
        // 持久存储, 实验模拟页判定点卡片从这读(不再依赖规则表/橙色生成按钮)
        if (entFuncs.count) {
            extern void mfAppPatchEntDumpsMerge(NSArray *);
            mfAppPatchEntDumpsMerge(entFuncs);
        }
        if (entFuncs.count) {
            [lines addObject:[NSString stringWithFormat:@"entitlement 判定点位: %lu 个(可 patch) — B 链, 实验模拟页左划 patch", (unsigned long)entFuncs.count]];
            for (NSDictionary *f in [entFuncs subarrayWithRange:NSMakeRange(0, MIN(4, entFuncs.count))]) {
                NSString *s = f[@"sym"] ?: @"";
                NSString *tail = s.length > 46 ? [s substringFromIndex:s.length - 46] : s;
                [lines addObject:[NSString stringWithFormat:@"  %@:%#lx …%@", f[@"img"], [f[@"vmaddr"] unsignedLongValue], tail]];
            }
        } else {
            // v2.59.3 双链分流升级: 点位 0 + SK2 形态 → **当场自动跑 A 链探测**(不再让用户手动二次点),
            //   结果(权益类名单+bool 字段)直接进证据行 — 侦查一次给全分流结论
            BOOL sk2Shape = [skType containsString:@"SK2"] || [skType containsString:@"SK1+SK2"];
            if (sk2Shape) {
                extern void mfChainAProbe(void);
                extern unsigned long mfChainAClassCount(void);
                extern NSArray *mfChainARowsSnapshot(void);
                mfChainAProbe();
                unsigned long nA = mfChainAClassCount();
                if (nA) {
                    [lines addObject:[NSString stringWithFormat:@"entitlement 判定点位: 0 — 典型 SK2 型(主二进制符号 strip) → 🅰️A链权益类 %lu 个:", nA]];
                    for (NSDictionary *d in [mfChainARowsSnapshot() subarrayWithRange:NSMakeRange(0, MIN(4ul, nA))]) {
                        NSMutableArray *bools = [NSMutableArray array];
                        for (NSString *iv in (NSArray *)d[@"ivars"])
                            if ([iv hasPrefix:@"bool "]) [bools addObject:[iv substringFromIndex:5]];
                        [lines addObject:[NSString stringWithFormat:@"  %@%@",
                            d[@"name"], bools.count ? [NSString stringWithFormat:@" (bool: %@)", [bools componentsJoinedByString:@"/"]] : @""]];
                    }
                } else {
                    [lines addObject:@"entitlement 判定点位: 0 · A链探测 0 命中 — 类名无权益语义, 待 fixup 重绑(开发中)"];
                }
            } else {
                [lines addObject:@"entitlement 判定点位: 未发现(已加载框架符号表无 Pro/Entitlement 判定函数)"];
            }
        }
    }

    // ---- 判定(动态拼接, 可叠加: Reflix = 云+mach 双面) ----
    BOOL cloud = cloudBrands.count > 0;
    // F7 服务器权益型(2026-09-06 mailnow 案定案): 无云 SDK + 纯 SK + WebView 权益标志(FlexCall/loadSuccess
    // /premium/no_ad/vip 类 JS 桥字段) → 权益本体在服务端会话, 本地解锁无意义
    BOOL serverSide = NO;
    BOOL skLocal = (BOOL)strstr(skType.UTF8String ?: "", "SK");   // v2.58.7: 提升作用域, verdict 链要用
    {
        static NSArray *kSrvPats;
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            kSrvPats = @[@"flexcall", @"loadsuccess", @"buyappitem", @"getappitemprice",
                         @"requestbuyappitem", @"user_number", @"usernumber"];
        });
        int srvHits = 0;
        for (NSString *pat in kSrvPats)
            if (mfRecFind(p, n, pat.UTF8String)) srvHits++;
        // SK 本地形态 + 无云验证 + JS 桥权益字段 → 服务器权益型
        if (srvHits >= 2 && !cloud && !mach && skLocal) serverSide = YES;
    }
    NSString *verdict;
    if (cloud && mach)      verdict = [NSString stringWithFormat:@"%@ 云端订阅验证 + 本地许可服务器(异常端口) — 双面, 先 mock 直试", cloudBrands.allObjects.firstObject];
    else if (cloud)         verdict = [NSString stringWithFormat:@"%@ 云端订阅验证 — mock 可直达", cloudBrands.allObjects.firstObject];
    else if (mach)          verdict = @"本地许可服务器(异常端口 MIG, Reflix/ScriptingPass 同族) — EXCPROBE 应答器可复刻";
    else if (serverSide)    verdict = @"服务器权益型(SK+WebView 桥权益标志) — 权益在服务端会话, 本地解锁无意义, 跳过";
    // v2.58.7: 纯 StoreKit 本地校验型分支(2.58.6 缺失 — SK2 明明已判定却显示"未发现订阅验证 SDK"兜底文案)
    else if (skLocal)       verdict = [NSString stringWithFormat:@"纯 StoreKit 本地校验型(%@ · %@) — 判定点已入库, 实验模拟页左划 patch", skType, validator];
    else                    verdict = @"未发现订阅验证 SDK";
    if (cloudBrands.count > 1) {
        NSString *names = [[cloudBrands.allObjects sortedArrayUsingSelector:@selector(compare)] componentsJoinedByString:@"/"];
        verdict = [verdict stringByReplacingOccurrencesOfString:cloudBrands.allObjects.firstObject
                                                     withString:[NSString stringWithFormat:@"%@(疑似多 SDK)", names]];
    }

    return @{@"verdict": verdict, @"lines": lines,
             @"cloud": @(cloud), @"mach": @(mach), @"srv": @(serverSide), @"sk": @(skLocal),
             @"sktype": skType, @"validator": validator,
             @"entFuncs": entFuncs};
}

// ===== 详情页(面板导航, 可滚动可长按选中复制) =====
static void mfReconShowDetailPage(NSDictionary *recon);   // 前置
@interface UIView (MFReconNav)
@end
@implementation UIView (MFReconNav)
- (void)mfReconGoLab {
    mfPopPage();          // 回扫描页
    mfShowLabPage();      // 跳实验模拟
}
- (void)mfReconGoExc {
    mfPopPage();          // v2.54.0: mach 型 → 跳实验模拟页开 EXCPROBE 应答器
    mfShowLabPage();
}
- (void)mfReconGoCapture {
    mfPopPage();
    mfShowNetAnalyzerPage();   // v2.50.0: 实时捕获开关在网络分析页(原误跳捕获列表)
}
// v2.57 链B交卷: 侦查卡点位 → swifttext 规则(JSON) → 实验模拟页 AppPatch 引擎
// patch 字节 = mov w0,#1; ret (20008052 c0035fd6) — Sb 返回值判定函数恒 true
- (void)mfReconGenEntPatch {
    NSArray *entFuncs = objc_getAssociatedObject(self, "reconEntFuncs");
    if (![entFuncs isKindOfClass:[NSArray class]] || !entFuncs.count) { mfToast(@"无点位数据"); return; }
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    // 现规则表 → 追加/更新本 bid 的 swifttext 条目
    extern NSString *mfAppPatchRulesJSON(void);
    extern void mfAppPatchSetRulesJSON(NSString *);
    NSArray *rules = nil;
    {
        NSData *rd = [mfAppPatchRulesJSON() dataUsingEncoding:NSUTF8StringEncoding];
        rules = [NSJSONSerialization JSONObjectWithData:rd options:0 error:nil];
        if (![rules isKindOfClass:[NSArray class]]) rules = @[];
    }
    // 目标 = F8 同款正向过滤(Sb 返回 + tF/vg 真函数; thunk/metadata 排除)
    NSMutableArray *patches = [NSMutableArray array];
    for (NSDictionary *f in entFuncs) {
        NSString *sym = f[@"sym"] ?: @"";
        if (![sym hasPrefix:@"_$s"]) continue;
        // thunk/async/特殊段后缀全排除(TQ0_/TA/Tu/yyYacfU/fA_/vpMV/Wl 等)
        if ([sym containsString:@"yyYacfU"] || [sym containsString:@"_fU_"] ||
            [sym containsString:@"cfC"] || [sym containsString:@"vpMV"] ||
            [sym containsString:@"vpfi"] || [sym containsString:@"WOh"] ||
            [sym containsString:@"WOe"] || [sym containsString:@"fA_"] ||
            [sym containsString:@"TQ"] || [sym hasSuffix:@"Tu"]) continue;
        if (![sym hasSuffix:@"tF"] && ![sym hasSuffix:@"vg"]) continue;   // 真函数本体
        if (![sym containsString:@"Sb"]) continue;                        // Bool 返回值型
        if ([sym containsString:@"ySb"]) continue;                        // v2.57.1: void 返回多参函数不打(refreshFromPurchaseState)
        [patches addObject:@{
            @"kind": @"swifttext",
            @"img": f[@"img"] ?: @"",
            @"sym": sym,
            @"new": @"20008052c0035fd6",   // mov w0,#1; ret
            @"note": @"ent恒真",
        }];
    }
    if (!patches.count) { mfToast(@"点位里无可 patch 判定函数(需 tF 返回值型)"); return; }
    // 更新 bid 规则
    NSMutableArray *newRules = [rules mutableCopy];
    NSUInteger found = NSNotFound;
    for (NSUInteger i = 0; i < newRules.count; i++)
        if ([[newRules[i] objectForKey:@"bid"] isEqualToString:bid]) { found = i; break; }
    NSDictionary *rule = @{@"bid": bid, @"ver": @"", @"note": @"侦查卡生成的 entitlement 判定 patch",
                           @"patches": patches};
    if (found != NSNotFound) {
        // 合并: 保留原 patches 里非 swifttext 的
        NSMutableArray *merged = [[newRules[found] objectForKey:@"patches"] mutableCopy] ?: [NSMutableArray array];
        for (NSDictionary *p in merged.copy) if ([p[@"kind"] isEqualToString:@"swifttext"]) [merged removeObject:p];
        [merged addObjectsFromArray:patches];
        newRules[found] = @{@"bid": bid, @"ver": @"", @"note": @"侦查卡生成的 entitlement 判定 patch",
                            @"patches": merged};
    } else [newRules addObject:rule];
    NSData *out = [NSJSONSerialization dataWithJSONObject:newRules options:NSJSONWritingPrettyPrinted error:nil];
    mfAppPatchSetRulesJSON([[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding]);
    // 开引擎 + 立即应用
    extern BOOL mfPrefBool(NSString *, BOOL);
    extern void mfSetBoolPref(NSString *, BOOL);
    extern void mfAppPatchBoot(void);
    NSString *pk = [NSString stringWithFormat:@"mfAppPatchEnabled_%@", bid];
    if (!mfPrefBool(pk, NO)) mfSetBoolPref(pk, YES);
    mfAppPatchBoot();
    mfToast([NSString stringWithFormat:@"已生成 %lu 条判定 patch + 引擎开启(冷启动自动重打)", (unsigned long)patches.count]);
    [self mfReconGoLab];
}
@end
static void mfReconShowDetailPage(NSDictionary *recon) {
    UIView *page = mfMakePage(@"侦查详情", YES);
    UILabel *v = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 32, 40)];
    v.text = recon[@"verdict"];
    v.font = [UIFont systemFontOfSize:13.5 weight:UIFontWeightSemibold];
    v.numberOfLines = 0;
    v.textColor = [recon[@"cloud"] boolValue] ? [UIColor systemGreenColor] :
                  [recon[@"mach"] boolValue] ? [UIColor systemPurpleColor] :
                  [recon[@"sk"] boolValue] ? [UIColor systemBlueColor] : [UIColor secondaryLabelColor];
    [page addSubview:v];

    CGFloat tvY = 96;
    NSArray *entFuncs = recon[@"entFuncs"];
    CGFloat btnY = 92;   // v2.58.7: 按钮纵向游标 — 修 y=92 多按钮叠放(2.58.6 只修了 cloud 分支, else-if 链换分支就复现)
    BOOL hasEnt = [entFuncs isKindOfClass:[NSArray class]] && entFuncs.count;
    if (hasEnt) {
        // v2.57 链B: 发现 entitlement 判定点位 → 一键生成 swifttext 规则进实验模拟页
        // v2.58: 扫描时已自动 merge 进 mfEntDumps, 此按钮退役 — 换为直通判定点卡片
        UIButton *gen = [UIButton buttonWithType:UIButtonTypeSystem];
        gen.frame = CGRectMake(16, btnY, g_mfCardW - 32, 38);
        gen.backgroundColor = [UIColor systemOrangeColor];
        gen.layer.cornerRadius = 9;
        [gen setTitle:[NSString stringWithFormat:@"🎯 判定点已入库(%lu) — 去实验模拟左划 patch", (unsigned long)entFuncs.count] forState:UIControlStateNormal];
        [gen setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        gen.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
        [gen addTarget:page action:NSSelectorFromString(@"mfReconGoLab") forControlEvents:UIControlEventTouchUpInside];
        objc_setAssociatedObject(page, "reconEntFuncs", entFuncs, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [page addSubview:gen];
        btnY += 44;
    }
    if ([recon[@"cloud"] boolValue]) {
        // v2.58: 云验证型也带判定点时补 patch 直通文案(链路不再断在按钮文案上)
        UIButton *lab = [UIButton buttonWithType:UIButtonTypeSystem];
        lab.frame = CGRectMake(16, btnY, g_mfCardW - 32, 38);
        lab.backgroundColor = [UIColor systemGreenColor];
        lab.layer.cornerRadius = 9;
        [lab setTitle:[NSString stringWithFormat:@"🧪 去实验模拟（云验证 mock%@）",
            hasEnt ? @" + 判定点 patch" : @""] forState:UIControlStateNormal];
        [lab setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        lab.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
        [lab addTarget:page action:NSSelectorFromString(@"mfReconGoLab") forControlEvents:UIControlEventTouchUpInside];
        objc_setAssociatedObject(page, "reconGoLab", @(1), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [page addSubview:lab];
        btnY += 44;
    } else if ([recon[@"mach"] boolValue]) {
        // v2.54.0: mach 型(本地许可服务器, Reflix/ScriptingPass 同族) → 引导去开 EXCPROBE 应答器
        UIButton *exc = [UIButton buttonWithType:UIButtonTypeSystem];
        exc.frame = CGRectMake(16, btnY, g_mfCardW - 32, 38);
        exc.backgroundColor = [UIColor systemPurpleColor];
        exc.layer.cornerRadius = 9;
        [exc setTitle:@"⏯ 去 IAP工具箱开 EXCPROBE 应答器" forState:UIControlStateNormal];
        [exc setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        exc.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
        [exc addTarget:page action:NSSelectorFromString(@"mfReconGoExc") forControlEvents:UIControlEventTouchUpInside];
        objc_setAssociatedObject(page, "reconGoExc", @(1), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [page addSubview:exc];
        btnY += 44;
    } else if (![recon[@"mach"] boolValue] && ![recon[@"sk"] boolValue]) {
        // v2.58.7: 纯兜底引导 — cloud/mach/SK 全空才显示(Scripting 类纯 SK 型已由 verdict+橙按钮覆盖, 不再误出)
        UIButton *cap = [UIButton buttonWithType:UIButtonTypeSystem];
        cap.frame = CGRectMake(16, btnY, g_mfCardW - 32, 38);
        cap.backgroundColor = [UIColor systemBlueColor];
        cap.layer.cornerRadius = 9;
        [cap setTitle:@"🌐 去网络分析开实时捕获 → 逛购买页 → 重扫" forState:UIControlStateNormal];
        [cap setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        cap.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
        [cap addTarget:page action:NSSelectorFromString(@"mfReconGoCapture") forControlEvents:UIControlEventTouchUpInside];
        [page addSubview:cap];
        btnY += 44;
    }
    tvY = btnY;
    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(12, tvY, g_mfCardW - 24, g_mfCardH - tvY - 12)];
    tv.backgroundColor = UIColor.clearColor;
    tv.editable = NO;
    tv.selectable = YES;   // 长按选中复制
    tv.font = [UIFont monospacedSystemFontOfSize:11.5 weight:UIFontWeightRegular];
    tv.textColor = [UIColor secondaryLabelColor];
    NSMutableString *body = [NSMutableString string];
    for (NSString *l in recon[@"lines"]) [body appendFormat:@"%@\n\n", l];
    tv.text = body;
    [page addSubview:tv];
    mfPushPage(page);
}

// ===== 置顶侦查卡 =====
@interface MFReconCard : UIButton
@end
@implementation MFReconCard
+ (void)showDetail:(UIButton *)btn {
    mfReconShowDetailPage(objc_getAssociatedObject(btn, "recon"));
}
@end

// SK 验证后回填第三类判定(纯 StoreKit/本地型) — recon 无云/mach 指纹时 SK 产品就是形态答案
void mfReconApplySKResult(NSDictionary *recon, UIView *page, NSString *topPid, BOOL isLifetime) {
    if ([recon[@"cloud"] boolValue] || [recon[@"mach"] boolValue]) return;   // 已有判定, 不覆盖
    MFReconCard *card = objc_getAssociatedObject(page, "reconCard");
    if (!card) return;
    NSMutableArray *lines = [recon[@"lines"] mutableCopy];
    [lines addObject:[NSString stringWithFormat:@"SK 验证通过: %@ (%@) — 无云验证 SDK/mach 端口 → 纯 StoreKit 本地校验型", topPid, isLifetime ? @"lifetime" : @"消耗型/订阅"]];
    NSString *val = recon[@"validator"] ?: @"无收据验证特征";
    NSString *sk = recon[@"sktype"] ?: @"未知";
    NSString *rec, *verdict;
    if ([sk containsString:@"SK2"] && ![sk containsString:@"SK1"]) {
        rec = @"SK2 JWS 型 — 判定点已入库(实验模拟页左划 patch 即恒真)";
        verdict = [NSString stringWithFormat:@"纯 StoreKit(SK2 JWS) — %@", topPid];
    } else if ([val containsString:@"TPInAppReceipt"] || [val containsString:@"CMS"]) {
        rec = @"收据验证型 → 推荐 L1 收据伪造 + L2 Sec 放行(2.50)";
        verdict = [NSString stringWithFormat:@"纯 StoreKit 本地验证(收据校验: %@) — %@", val, topPid];
    } else {
        rec = @"队列信任候选 → 推荐 L0 队列伪造试探(2.49)";
        verdict = [NSString stringWithFormat:@"纯 StoreKit 本地验证(无收据校验特征) — %@", topPid];
    }
    [lines addObject:rec];
    NSMutableDictionary *upd = [recon mutableCopy];
    upd[@"lines"] = lines;
    recon = upd;
    objc_setAssociatedObject(card, "recon", recon, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "reconCard", card, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    UILabel *v = [card viewWithTag:901], *sub = [card viewWithTag:902];
    v.text = [NSString stringWithFormat:@"侦查: %@", verdict];
    v.textColor = [UIColor systemBlueColor];
    sub.text = [NSString stringWithFormat:@"%lu 条证据 · 点看详情", (unsigned long)lines.count];
}

// 返回高度 52 的置顶卡(y 由调用方定)
UIView *mfReconMakeCard(NSDictionary *recon) {
    MFReconCard *card = [MFReconCard buttonWithType:UIButtonTypeSystem];
    card.frame = CGRectMake(16, 46, g_mfCardW - 32, 52);
    card.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    card.layer.cornerRadius = 10;
    BOOL c = [recon[@"cloud"] boolValue], m = [recon[@"mach"] boolValue], sk = [recon[@"sk"] boolValue];
    UILabel *v = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, (g_mfCardW - 32) - 24, 18)];
    v.tag = 901;
    v.text = [NSString stringWithFormat:@"侦查: %@", recon[@"verdict"]];
    v.font = [UIFont systemFontOfSize:12.5 weight:UIFontWeightSemibold];
    v.textColor = (c && m) ? [UIColor systemIndigoColor] : c ? [UIColor systemGreenColor] :
                  m ? [UIColor systemPurpleColor] : sk ? [UIColor systemBlueColor] : [UIColor secondaryLabelColor];
    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectMake(12, 28, (g_mfCardW - 32) - 24, 16)];
    sub.tag = 902;
    sub.text = [NSString stringWithFormat:@"%lu 条证据 · 点看详情", (unsigned long)[recon[@"lines"] count]];
    sub.font = [UIFont systemFontOfSize:10.5];
    sub.textColor = [UIColor tertiaryLabelColor];
    [card addSubview:v]; [card addSubview:sub];
    objc_setAssociatedObject(card, "recon", recon, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [card addTarget:[MFReconCard class] action:@selector(showDetail:) forControlEvents:UIControlEventTouchUpInside];
    return card;
}
