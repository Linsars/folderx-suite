// MFRecon.m — 内购模式一次性侦查(扫描时点指纹, 零 hook 零常驻, 纯读)
// 判据 v2(2026-09-05 实测纠偏):
//   云验证类   — RC/SW/Adapty 等订阅 SDK 品牌串/域名串/RC 缓存 → MFSubInject mock 直达
//   mach 协议类 — ★ 判据收紧: 进程异常端口表里存在【独立 BREAKPOINT 条目】(mask==0x40
//               且 beh==MACH_EXCEPTION_CODES|EXCEPTION_STATE 且 flv==ARM_THREAD_STATE64)
//               = 伴侣 dylib 注册的本地许可服务器(2.38.4 实测指纹 mask=0x40 beh=-2147483646 flv=6)
//   ✗ 已废弃 brk 大立即数判据 — 2.39.7 旧注释"app 查询=brk #0x965…"系误读, 终案实锤陷阱为
//     vendor 运行时写入的常规 brk, 静态二进制无此指纹(用户实测 29639 brk 全编译器常规)
//   ✗ 系统级 crash handler(mask 混合 0x104e/IDENTITY/flv5)不再误标 — 目标型必须是独立条目

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>

// v2.58.26: 小写不敏感子串(词表全小写, 输入先转小写) — strstr 大小写敏感,
// ServeLog 驼峰串(Entitle/Subscription)全 miss 的 dbg_25 定谳修复
static const char *mfStrCaseStr(const char *hay, const char *needle) {
    if (!hay || !needle) return NULL;
    size_t nl = strlen(needle);
    if (!nl) return hay;
    for (const char *p = hay; *p; p++) {
        size_t k = 0;
        while (k < nl && p[k] && p[k] == needle[k]) k++;
        if (k == nl) return p;
    }
    return NULL;
}

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <string.h>
#import <objc/runtime.h>
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

// v2.58.58: 指令字 → 内存序 hex — 执行端 apHexToBytes 按内存字节序解析
//   (NOP 0xD503201F → "1f2003d5"), 扫描端 %08x 是值序会倒序翻转,
//   old 校验必 mismatch / 新字节全错。统一在扫描端转内存序。
static NSString *mfLeHex(uint32_t w) {
    return [NSString stringWithFormat:@"%02x%02x%02x%02x",
            w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, (w >> 24) & 0xFF];
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

// ====================================================================
// F8v2 rev3 (2026-09-12): SK2 判定点运行时定位 — bind 链磁盘直读法
// v1(2.58.9) dlsym 名字语义 bug(带 _ 传名全 miss) → v2(2.58.10) 修复后
// yimuliaoran 实战(dbg_11)暴露三个新问题:
//   ① dlsym 解析面不全: Product 系符号能解析, Transaction 系 miss →
//      扫到的全是 Product 显示层函数(证据行 score 全 0), 判定函数漏网
//   ② nCall 128 截断: 大 app SK 调用点超限, 排位靠后的判定函数被砍
//   ③ patch 后重扫污染: 已 patch 函数头(mov w0,#1;ret)不再是 prologue,
//      回溯越过真头落到前一函数体内 → 两次会话点位漂移 ~0x1A0
// rev3(2.58.12 后): rev2 的 dladdr 分类法在 iOS17+ 全灭(dbg_13 stub-match
// 实锤) — dyld 源码定谳: dladdr 走 findClosestSymbol(需 local symtab), cache 内
// image 的 local symbols 在独立 .symbols 文件运行时不可用 → dli_sname 全 null。
// 回到 bind 链路线(2.58.9 放弃的), 但链改读**磁盘文件**: dyld applyFixups 只重写
// __DATA 里的 GOT slot 值, 磁盘上链描述(page_starts/next/ordinal)原样保留 —
// Python 静态版 yimuliaoran 596/596 stub 全解 / gongju 1468/1468 全解实证。
// fixups blob 仍在内存读(在 __LINKEDIT, dyld 只读不写)。
//   磁盘链走查 → slot_vmaddr→import ordinal 表(4096 上限)
//   → __stubs 解码(adrp 完整掩码含 immlo≠0) → slot 查表 → 符号名(imports 池)
//   → SK 词表(8StoreKit)过滤 → SK stub 集(带名字, 评分用)
//   → __TEXT bl/b 扫描(上限 1024) → prologue 归属(pacibsp/stp/sub-sp +
//      自家 patch 头识别, patch 后重扫点位稳定) → 评分 → top6 @0x 点位
// ====================================================================
// ====================================================================
// v2.58.171 识别层重构: 框架 Swift 权益门 = 模块归属过滤 + 语义打分(替代单一 strstr 白名单)
//   病(dbg_158): kEntPats strstr 白名单 → 改名/混淆即 miss(找不着), 通用词根撞名即误判
//   (NIOPosix.add/Tokenizers.postProcess 恰好返 Bool 被当真门)。与 sk2plan 计划名字面量同病。
//   治: ① 模块归属 — Swift mangled _$s<len><module>, module 必须 == 框架 leaf 名
//       → 结构性杀掉 vendored 第三方库(Tokenizers/NIOPosix/GRDB, 模块名≠框架名)噪声, 零词表。
//       ② 语义打分 — 强锚(战役验证真门)/权益词/判定语义分层, score>0 才收, 降序 top N。
//       裸 pro/vip 太短易撞(Provider→pro)用长 token, score 0 自动淘汰无语义 getter。

// mangled _$s<len><module>... → 提取 module 名(小写)。失败返回 NO。
static BOOL mfMangledModule(const char *nm, char *out, size_t outsz) {
    if (!nm || nm[0] != '_' || nm[1] != '$' || nm[2] != 's') return NO;
    const char *p = nm + 3;
    int len = 0;
    while (*p >= '0' && *p <= '9') { len = len * 10 + (*p - '0'); p++; }
    if (len <= 0 || len > 60 || (size_t)len >= outsz) return NO;
    for (int i = 0; i < len; i++) {
        if (!p[i]) return NO;
        out[i] = (char)tolower((unsigned char)p[i]);
    }
    out[len] = 0;
    return YES;
}

// 框架权益门语义打分(小写 mangled 全名) — score>0 才是候选, 越高越像真门。
// 框架权益门语义打分(小写 mangled 全名) — 返回值 >0 才是候选, 越高越像真门。
//   负向词命中直接返 -1(陷阱门: 打了有害或无效, 绝不入库)。
static int mfEntSemScore(const char *lower) {
    // ★负向词优先: 试用资格/反作弊/促销/系统权限 — 打这些不解锁, 甚至反效果(dbg_159:
    //   isEligibleForIntroOffer 恒真 → "年度会员变 7 天免费")。命中即弃。
    const char *neg[] = {"intro","trial","freetrial","cheat","promo","coupon","referr",
                         "speechrecognition","locationservice","isauthorizedforwidget",
                         "calendar","notification","microphone","camera","contacts","photolibrary",NULL};
    for (int i=0; neg[i]; i++) if (strstr(lower, neg[i])) return -1;
    int s = 0;
    // 强锚: scripting 战役验证过的真门族 + 通用权益守卫命名(具体, 不易撞)
    const char *strong[] = {"proaccessguard","accessguard","entitlementoracle","entitlement",
                            "hasvalidtoken","hasvalidd5token","hasproaccess","hascd0",
                            "requirecapab","requirec0","provalidated","isprovalid",NULL};
    for (int i=0; strong[i]; i++) if (strstr(lower, strong[i])) { s += 10; break; }
    // 权益词(长 token, 不撞): premium/unlock/subscri/purchas/lifetime/upgrade/license
    const char *ent[] = {"premium","unlocked","unlockpro","issubscri","subscribed","purchased",
                         "haspurchas","islifetime","isforever","isperpetual","upgraded","licensed",
                         "ispaiduser","ispremiumuser",NULL};
    for (int i=0; ent[i]; i++) if (strstr(lower, ent[i])) { s += 5; break; }
    // 判定语义: auth/manage/vip/member/paid(覆盖 canManageModels/isClaudeAuthActive/isGPTAuthActive)
    //   注: iseligible 从此层移除 — 它几乎只出现在 isEligibleForIntro(试用), 已被负向词拦。
    const char *sem[] = {"authactive","isauth","canmanage","manages","ismember","membership",
                         "isvip","ispaid","canaccess","isactivated","isunlocked","hasaccess",NULL};
    for (int i=0; sem[i]; i++) if (strstr(lower, sem[i])) { s += 3; break; }
    return s;
}

static NSDictionary *mfReconF8v2Scan(void) {
    @autoreleasepool {
    // ---- 锚点1: 主二进制 header/slide ----
    const struct mach_header_64 *mh = NULL;
    intptr_t slide = 0;
    const char *mainPath = NULL;
    uint32_t ic = _dyld_image_count();
    for (uint32_t i = 0; i < ic; i++) {
        const char *n = _dyld_get_image_name(i);
        if (!n) continue;
        // 主二进制 = 路径含 .app/ 且后面不带 .framework/.dylib/.bundle
        const char *ap = strstr(n, ".app/");
        if (!ap || !ap[5]) continue;
        if (strstr(ap + 5, ".framework") || strstr(ap + 5, ".dylib") || strstr(ap + 5, ".bundle")) continue;
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        mh = (const struct mach_header_64 *)h;
        slide = _dyld_get_image_vmaddr_slide(i);
        mainPath = n;
        break;
    }
    if (!mh) return nil;
    // 分步日志 — 链条长, 每个断点带步骤名, 验收一次定位
    // v2.58.120: bail 语义改"优雅降级" — 旧版 return nil 会让调用方拿到 nil 字典,
    //   sk2pts/cands 全 nil, 后续依赖(判型/框架扫描)连锁失效(dbg_113 scripting:
    //   主二进制无 SK 符号 → stub-match bail → 判型全丢)。
    //   现在: 返回空结构而非 nil, 调用方照常消费; 并明确日志"交框架扫描兜底"。
    #define F8V2_BAIL(tag) do { mfLog(@"[f8v2] ✗ 步骤:%s 中断(降级返回空结果, 侦查继续)", tag); \
        return @{@"cands": @[], @"ncalls": @0, @"skstubs": @0, @"skimports": @0, @"sk2pts": @[]}; } while (0)

    // ---- LC: __text/__stubs section(rev2 不再需要 fixups 表) ----
    const struct load_command *lc = (const struct load_command *)((const uint8_t *)mh + sizeof(struct mach_header_64));
    uint64_t textVM = 0, textSize = 0, stubVM = 0, stubSize = 0, textFileOff = 0;
    uint64_t baseVM = 0;   // v2.58.52: __TEXT vmaddr(sk2pro 串定位)
    uint64_t constSecVM[8] = {0}; uint64_t constSecSize[8] = {0}; int nConstSec = 0;
    // v2.58.79: __cstring section — SKU 串扫描用(dbg_81 定谳: 旧实现扫 __text
    //   导致零命中, sk2br 块静默跳过)
    uint64_t cstrVM = 0, cstrSize = 0, cstrFileOff = 0;
    for (uint32_t c = 0; c < mh->ncmds; c++, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
        if (lc->cmd != LC_SEGMENT_64) continue;
        const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
        if (!strcmp(sg->segname, "__TEXT")) baseVM = sg->vmaddr;
        const struct section_64 *sc = (const struct section_64 *)((const uint8_t *)sg + sizeof(struct segment_command_64));
        for (uint32_t s = 0; s < sg->nsects; s++, sc++) {
            if (!strcmp(sc->segname, "__TEXT") && !strcmp(sc->sectname, "__text")) { textVM = sc->addr; textSize = sc->size; textFileOff = sc->offset; }
            if (!strcmp(sc->segname, "__TEXT") && !strcmp(sc->sectname, "__stubs")) { stubVM = sc->addr; stubSize = sc->size; }
            if (!strcmp(sc->segname, "__TEXT") && !strcmp(sc->sectname, "__cstring")) { cstrVM = sc->addr; cstrSize = sc->size; cstrFileOff = sc->offset; }
            // v2.58.52: const 段收集(oslog fmt 槽在 __const/__constg_swiftt — sk2pro 用)
            if (!strcmp(sc->segname, "__TEXT") && !strncmp(sc->sectname, "__const", 7) && nConstSec < 8) {
                constSecVM[nConstSec] = sc->addr; constSecSize[nConstSec] = sc->size; nConstSec++;
            }
        }
    }
    if (!textSize || !stubSize) F8V2_BAIL("lc-parse");

    // ---- stub 步进探测: 12B 常规 / 16B auth 变体 ----
    // 探测窗口 = 区内前 32 项滑窗(不止前 4 — yimuliaoran 开头几项形态混杂,
    // dbg_12 stub-probe bail 实锤); 3/32 合法即定步进, 全失败回退 12B
    // (分类循环有 adrp+ldr 形态过滤, 错位项自然跳过, 只损失覆盖率不误报)
    uint64_t stubStep = 0;
    for (uint64_t st = 12; st <= 16; st += 4) {
        int wellFormed = 0, checked = 0;
        for (uint64_t off = 0; off + 12 <= stubSize && checked < 32; off += st) {
            uintptr_t a = (uintptr_t)stubVM + (uintptr_t)slide + off;
            uint32_t i1 = *(const uint32_t *)a, i2 = *(const uint32_t *)(a + 4), i3 = *(const uint32_t *)(a + 8);
            checked++;
            // adrp 完整判定 = (ins & 0x9F000000)==0x90000000 — 0x90/0xb0/0xd0 开头都是 adrp(immlo 在低2位);
            // v2.58.11 只查 >>26==0x24 漏掉 immlo≠0 形态 → yimuliaoran 前7个stub全BAD → stub-probe bail(dbg_12 实锤)
            if ((i1 & 0x9F000000) == 0x90000000 && (i2 & 0xFFC00000) == 0xF9400000 && (i3 & 0xFFFFFC1F) == 0xD61F0000) wellFormed++;
        }
        if (wellFormed >= 3) { stubStep = st; break; }
    }
    if (!stubStep) stubStep = 12;   // 探测失败不 bail — 回退常规, 分类循环自滤错位项
    mfLog(@"[f8v2] stub区=%lluB 步进=%llu", (unsigned long long)stubSize, (unsigned long long)stubStep);

    // ---- stub 分类 rev3: bind 链直读(零符号查询, 纯 LINKEDIT 元数据) ----
    // dyld 源码定谳: dladdr 走 findClosestSymbol(需 local symtab) — iOS17+ cache
    // local symbols 在独立 .symbols 文件运行时不可用 → dli_sname 全 null 全灭(dbg_13
    // stub-match 实锤)。dlsym 走 export trie 可用, 但只给一个地址不认 stub。
    // rev3 = 回 2.58.9 的 bind 链路线: dyld 只改写 GOT slot 的**值**, LINKEDIT 里
    // 的链描述(page_starts/next/ordinal)原样保留 — 静态 Python 版 596/596 全解同款算法
    struct { uint64_t vmaddr, vmsize, fileoff, filesize; const uint8_t *mem; } segs[8];
    int nSegs = 0;
    lc = (const struct load_command *)((const uint8_t *)mh + sizeof(struct mach_header_64));   // 重置! 上个循环已走到底(dbg_14 fixblob-locate 实锤)
    for (uint32_t c = 0; c < mh->ncmds; c++, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
        if (lc->cmd != LC_SEGMENT_64) continue;
        const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
        if (nSegs < 8) { segs[nSegs].vmaddr = sg->vmaddr; segs[nSegs].vmsize = sg->vmsize;
                         segs[nSegs].fileoff = sg->fileoff; segs[nSegs].filesize = sg->filesize;
                         segs[nSegs].mem = (const uint8_t *)((uintptr_t)sg->vmaddr + (uintptr_t)slide);
                         nSegs++; }
    }
    // fixups blob: LC_DYLD_CHAINED_FIXUPS dataoff → 定位到内存(找覆盖段)
    uint64_t fixOff = 0, fixSize = 0;
    lc = (const struct load_command *)((const uint8_t *)mh + sizeof(struct mach_header_64));
    for (uint32_t c = 0; c < mh->ncmds; c++, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
        if (lc->cmd == LC_DYLD_CHAINED_FIXUPS || lc->cmd == 0x80000034) {
            const struct linkedit_data_command *ld = (const struct linkedit_data_command *)lc;
            fixOff = ld->dataoff; fixSize = ld->datasize;
        }
    }
    if (!fixSize || fixSize < 28) F8V2_BAIL("fixblob-locate");
    const uint8_t *fixBase = NULL;
    for (int s = 0; s < nSegs; s++)
        if (fixOff >= segs[s].fileoff && fixOff < segs[s].fileoff + segs[s].filesize) {
            fixBase = segs[s].mem + (fixOff - segs[s].fileoff);
            break;
        }
    if (!fixBase) F8V2_BAIL("fixblob-locate");
    uint32_t startsOff = *(const uint32_t *)(fixBase + 4);
    uint32_t importsOff = *(const uint32_t *)(fixBase + 8);
    uint32_t symbolsOff = *(const uint32_t *)(fixBase + 12);
    uint32_t importsCount = *(const uint32_t *)(fixBase + 16);
    uint32_t importsFormat = *(const uint32_t *)(fixBase + 20);
    if (importsFormat != 1 || !importsCount) F8V2_BAIL("imports-format");
    if (importsOff + 4ull * (uint64_t)importsCount > fixSize) F8V2_BAIL("imports-format");
    const char *symPool = (const char *)(fixBase + symbolsOff);
    const char *symPoolEnd = (const char *)fixBase + fixSize;   // 名字池尾部 NUL 兜底(blob 尾 = 池尾)

    // dyld_chained_starts_in_image: seg_count u32 @0, seg_info_offset[seg_count] u32 @4
    // (相对 startsOff 的偏移, 实测 yimuliaoran: 0,0,0x18,0x38,0 — 后两个是 __DATA_CONST/__DATA)
    if (startsOff + 4 > fixSize) F8V2_BAIL("fixblob-size");
    uint32_t segCount = *(const uint32_t *)(fixBase + startsOff);
    if (segCount > 16 || startsOff + 4 + segCount * 4 > fixSize) F8V2_BAIL("fixblob-size");

    // ---- bind 链走查: 必须读磁盘文件 ----
    // dyld applyFixups 会把 __DATA/__DATA_CONST 里的链 qword 重写成最终指针(ordinal/next
    // 位域被毁) — 内存走链读到的全是已 bind 指针, 2.58.9 因此放弃此路。但磁盘文件里
    // 链描述原样保留(Python 静态版 596/596 全解实证)。fixups blob 本身在 __LINKEDIT
    // (dyld 只读不写) — 内存读 fixBase 沿用。
    // 链 qword(arm64): ordinal:24 | addend:8 | reserved:19 | next:12(4B步进) | bind:1(bit63)
    NSData *bin = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:mainPath]
                                         options:NSDataReadingMappedIfSafe error:nil];
    if (!bin.length) F8V2_BAIL("disk-read");
    const uint8_t *bd = (const uint8_t *)bin.bytes;
    uint64_t binLen = (uint64_t)bin.length;
    #define F8V2_MAXSLOT 4096
    static uint64_t slotVM[F8V2_MAXSLOT]; static uint32_t slotOrd[F8V2_MAXSLOT]; int nSlot = 0;
    uint64_t nWalkTotal = 0;                                    // v2.58.118: 走查总条数(诊断)
    // v2.58.118: 过滤式走查 — 旧版存全量 slot(4096 上限)在 bplayer 被截断(总 30464 条,
    //   retain 的 slot 在第 4207 位) → 真门检测永远拿不到 retain 符号(dbg_109 实锤:
    //   bind链 slot=4096 卡满 + 真门形态 0 次)。现在: 走查跑完全量, 只入库关心符号
    //   (SK 命名空间 + bridgeObjectRetain) — 实测 30464 → 54 条, 与上限彻底解耦。
    static uint8_t wantOrd[65536]; uint32_t nWant = 0;
    BOOL wantFilter = NO;
    if (importsCount < 65536) {
        memset(wantOrd, 0, sizeof(wantOrd));
        for (uint32_t o = 0; o < importsCount; o++) {
            const char *cand = symPool + (*(const uint32_t *)(fixBase + importsOff + 4 * (uint64_t)o) >> 9);
            if (cand < symPool || cand >= symPoolEnd) continue;
            if (strstr(cand, "8StoreKit") || strstr(cand, "bridgeObjectRetain")) { wantOrd[o] = 1; nWant++; }
        }
        if (nWant > 0) wantFilter = YES;    // v2.58.118: nWant=0 回退全量(防 imports 解析异常空表)
    }
    mfLog(@"[f8v2] 关心符号 ordinal=%u (SK+retain, imports=%u)", nWant, importsCount);
    for (uint32_t si = 0; si < segCount; si++) {
        uint32_t segInfoOff = *(const uint32_t *)(fixBase + startsOff + 4 + si * 4);
        if (!segInfoOff) continue;                              // 该段无 fixups
        const uint8_t *sgB = fixBase + startsOff + segInfoOff;
        // dyld_chained_starts_in_segment: size u32@0, page_size u16@4, format u16@6, segment_offset u64@8, max_valid u32@16, page_count u16@20, page_start[]@22
        if ((uintptr_t)sgB + 22 > (uintptr_t)fixBase + fixSize) continue;
        uint16_t pageSize = *(const uint16_t *)(sgB + 4);
        uint16_t pageCount = *(const uint16_t *)(sgB + 20);
        // segment_offset 是相对镜像基址的偏移(0x104000), 不是绝对 vmaddr(dbg_15 bind-walk 实锤)
        // 基址 = 第一个 vmaddr≠0 的段(__PAGEZERO 是 0, segs[0] 不能当基址用)
        uint64_t imgBase = 0;
        for (int s = 0; s < nSegs; s++) if (segs[s].vmaddr) { imgBase = segs[s].vmaddr; break; }
        uint64_t segVM = *(const uint64_t *)(sgB + 8) + imgBase;
        // 段的磁盘位置: 查 LC 段表 — 用 fileoff 定位磁盘链
        uint64_t segFO = 0; BOOL segFound = NO;
        for (int s = 0; s < nSegs; s++)
            if (segs[s].vmaddr == segVM) { segFO = segs[s].fileoff; segFound = YES; break; }
        if (!segFound) continue;
        if ((uintptr_t)sgB + 22 + 2 * (uint64_t)pageCount > (uintptr_t)fixBase + fixSize) continue;
        const uint16_t *pgStart = (const uint16_t *)(sgB + 22);
        const uint16_t *multi = pgStart + pageCount;
        for (uint32_t pi = 0; pi < pageCount; pi++) {
            uint16_t st = pgStart[pi];
            if (st == 0xFFFF) continue;
            uint16_t chainStarts[32]; int nCS = 0;               // multi-entry 链表展开
            if (st & 0x8000) {
                uint32_t ci = st & 0x7FFF;
                while (nCS < 32) {
                    if ((uintptr_t)multi + 2 * ci + 2 > (uintptr_t)fixBase + fixSize) break;
                    uint16_t v = multi[ci];
                    chainStarts[nCS++] = v & 0x7FFF;
                    if (v & 0x8000) break;
                    ci++;
                }
            } else chainStarts[nCS++] = st;
            for (int ci2 = 0; ci2 < nCS; ci2++) {
                uint32_t cur = chainStarts[ci2]; int guard = 0;
                while (guard++ < 100000) {
                    uint64_t fo = segFO + (uint64_t)pi * pageSize + cur;
                    if (fo + 8 > binLen) break;                  // 越界(段截断/紧凑布局)
                    uint64_t q = *(const uint64_t *)(bd + fo);    // 磁盘链 qword — bind 元数据原样
                    if (q >> 63) {                               // bind entry
                        uint32_t ord = (uint32_t)(q & 0xFFFFFF);
                        nWalkTotal++;                            // v2.58.118: 诊断 — 走查总条数
                        // v2.58.118: 只入库关心符号(SK + retain) — 否则 4096 上限截断(见上)
                        BOOL want = wantFilter ? (ord < 65536 && wantOrd[ord]) : (ord < importsCount);
                        if (want && nSlot < F8V2_MAXSLOT) { slotVM[nSlot] = segVM + (uint64_t)pi * pageSize + cur; slotOrd[nSlot] = ord; nSlot++; }
                    }
                    uint32_t nxt = (uint32_t)((q >> 51) & 0xFFF);
                    if (!nxt) break;
                    cur += nxt * 4;
                }
            }
        }
    }
    mfLog(@"[f8v2] bind链 slot=%d (走查总=%llu imports=%u)", nSlot, (unsigned long long)nWalkTotal, importsCount);
    if (!nSlot) F8V2_BAIL("bind-walk");

    // ---- stub → slot 匹配 → SK 词表过滤 ----
    // slot 查找 O(nSlot)×596 — nSlot~1600 可接受; skStubNames 直接指向 symPool(静态区, 生命周期 OK)
    uint64_t skStubVM[128]; const char *skStubNames[128]; int nSkStub = 0;
    // v2.58.118: retain stub 小表 — 真门形态检测用。走查已按名过滤, retain 的 slot
    //   必定在表里(旧版 4096 截断导致解名失败 → isRealGate 恒 NO)。
    uint64_t retainStubVM[8]; int nRetainStub = 0;
    // v2.58.114 sk2vfy: 验证类 stub 独立存一份(含非 SK 前缀的 StoreKit 符号,
    //   如 TransactionV19currentEntitlements / VerificationResult), 供下方判据点扫描用
    uint64_t vfyStubVM[32]; const char *vfyStubNames[32]; int nVfyStub = 0;
    static const char *kVfyNames[] = { "currentEntitlements", "jwsRepresentation", "payloadValue",
                                       "revocationDate", "expirationDate", "TransactionV7updates",
                                       "makeAsyncIterator", "EnvironmentV8rawValue" };
    int nCE = 0, nUpd = 0, nPID = 0;
    // v2.58.117: 循环条件解耦 — 旧版 `nSkStub < 128` 会让遍历在 StoreKit stub 满额时
    //   整体退出, 后面的 stub(含 _swift_bridgeObjectRetain)永远扫不到 → 真门检测失效。
    //   现在: 遍历必须跑完整个 stub 区; 各表各自受自己的容量上限约束。
    for (uint64_t off = 0; off + 12 <= stubSize; off += stubStep) {
        uintptr_t a = (uintptr_t)stubVM + (uintptr_t)slide + off;
        uint32_t ins1 = *(const uint32_t *)a, ins2 = *(const uint32_t *)(a + 4);
        if ((ins1 & 0x9F000000) != 0x90000000) continue;       // adrp?(含 immlo≠0 形态)
        if ((ins2 & 0xFFC00000) != 0xF9400000) continue;    // ldr x16,[xN,#imm12*8]?
        int64_t imm = (int64_t)((((ins1 >> 5) & 0x7FFFF) << 2) | ((ins1 >> 29) & 3));
        if (imm & (1 << 20)) imm -= (int64_t)(1 << 21);
        uint64_t page = (stubVM + off) & ~0xFFFULL;
        if (imm >= 0) page += (uint64_t)imm << 12; else page -= (uint64_t)(-imm) << 12;
        uint64_t slot = page + ((((ins2 >> 10) & 0xFFF) << 3));
        const char *nm = NULL;
        for (int k = 0; k < nSlot; k++) if (slotVM[k] == slot) {
            uint32_t o = slotOrd[k];
            if (importsOff + 4ull * (o+1) > fixSize) break;
            const char *cand = symPool + (*(const uint32_t *)(fixBase + importsOff + 4 * (uint64_t)o) >> 9);
            if (cand < symPool || cand >= symPoolEnd) break;    // 名偏移越界(池尾保护)
            // v2.58.118: retain stub 单独收(真门形态检测用)
            if (strstr(cand, "bridgeObjectRetain")) {
                if (nRetainStub < 8) { retainStubVM[nRetainStub] = stubVM + off; nRetainStub++; }
                break;
            }
            if (strstr(cand, "8StoreKit")) nm = cand;
            break;
        }
        if (!nm) continue;
        if (nSkStub < 128) {
            skStubVM[nSkStub] = stubVM + off; skStubNames[nSkStub] = nm; nSkStub++;
        }
        // v2.58.114 sk2vfy: 验证类符号单独收(所有验证符号都在 8StoreKit 命名空间内,
        //   通过 nm 判定即可 — 是 C1 的锚点)
        if (nVfyStub < 32) {
            for (int w2 = 0; w2 < 8; w2++)
                if (strstr(nm, kVfyNames[w2])) {
                    vfyStubVM[nVfyStub] = stubVM + off;
                    vfyStubNames[nVfyStub] = nm;
                    nVfyStub++;
                    break;
                }
        }
        if (strstr(nm, "currentEntitlements")) nCE++;
        if (strstr(nm, "7updates")) nUpd++;
        if (strstr(nm, "9productID")) nPID++;
    }
    // v2.58.120: "主二进制无 SK 消费链"是合法形态(scripting: SK 全在 ScriptingKit.framework),
    //   旧版这里直接 bail 让判型链断(dbg_113)。改为优雅降级 + 明确语义, 由框架扫描兜底。
    if (!nSkStub) F8V2_BAIL("主二进制无 SK 消费链(交框架扫描兜底)");
    mfLog(@"[f8v2] SK stub=%d (currentEntitlements=%d updates=%d productID=%d) retain stub=%d", nSkStub, nCE, nUpd, nPID, nRetainStub);
    // v2.58.130: slide 诊断 — 函数级锚定的范围判界靠它(旧版 baseVM vs 运行时地址 bug)
    mfLog(@"[f8v2] slide=%#llx baseVM=%#llx textVM=%#llx (锚定判界空间)", (unsigned long long)slide, (unsigned long long)baseVM, (unsigned long long)textVM);
    // v2.58.16: stub 明细日志 — dbg_16 实锤运行时 SK stub=22 vs 静态 17, 差 5 个
    // 假 stub 污染评分(垃圾候选 calls=10 score 错位), 名字打出来一次定位
    for (int k = 0; k < nSkStub && k < 32; k++)
        mfLog(@"[f8v2] stub[%d] @%#llx %s", k, (unsigned long long)skStubVM[k], skStubNames[k] ? skStubNames[k] : "(null)");

    // ---- __TEXT bl/b 扫描 → SK 调用点(上限 1024 — v2 的 128 截断教训) ----
    enum { kMaxCall = 1024 };
    static uint64_t callPC[kMaxCall]; static int callSKIdx[kMaxCall];
    int nCall = 0;
    for (uint64_t off = 0; off + 4 <= textSize && nCall < kMaxCall; off += 4) {
        uint32_t ins = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off);
        uint32_t op = ins >> 26;
        if (op != 0x25 && op != 0x05) continue;       // bl / b
        int64_t imm = (int64_t)(ins & 0x3FFFFFF);
        if (imm & (1 << 25)) imm -= (int64_t)(1 << 26);
        uint64_t tgt = textVM + off + ((uint64_t)imm << 2);
        for (int k = 0; k < nSkStub; k++)
            if (skStubVM[k] == tgt) { callPC[nCall] = textVM + off; callSKIdx[nCall] = k; nCall++; break; }
    }
    if (!nCall) F8V2_BAIL("bl-scan");

    // ---- prologue 归属 + 评分 ----
    // 头形态: pacibsp / stp 任意对 pre-index(不只 x29,x30 — yimuliaoran 显示层
    // a9ba6ffc=stp x28,x27,[sp,#-N]! 实锤漏形态) / sub sp,sp,#N(Swift async 无帧指针)
    // + 自家 patch 头(mov w0,#1;ret)识别 — 已 patch 函数真头被毁, 认它保 patch 后重扫稳定
    // 评分: currentEntitlements+5 / productID+3 / updates+2 / TransactionVMa+2 /
    //   products+2 / purchase+1 / finish-requestReview-1; Product 显示系=0
    NSMutableArray *cands = [NSMutableArray array];
    for (int i = 0; i < nCall; i++) {
        uint64_t pc = callPC[i];
        uint64_t head = 0; BOOL headOK = NO;
        for (uint64_t back = 0; back < 0x10000; back += 4) {
            if (pc < textVM + back) break;
            uintptr_t ha = (uintptr_t)(pc - back) + (uintptr_t)slide;
            uint32_t q = *(const uint32_t *)ha;
            if (q == 0xD503237F) { head = pc - back; headOK = YES; break; }                     // pacibsp
            if ((q & 0x7FC00000) == 0x29800000 && ((q >> 5) & 0x1F) == 31) { head = pc - back; headOK = YES; break; } // stp Xt,Xt,[sp,#-N]! pre(任意寄存器对)
            if ((q & 0xFFC003FF) == 0xD10003FF && ((q >> 10) & 0xFFF)) { head = pc - back; headOK = YES; break; } // sub sp,sp,#N
            if (q == 0x52800020 && *(const uint32_t *)(ha + 4) == 0xD65F03C0) { head = pc - back; headOK = YES; break; } // 自家 patch 头
        }
        if (!headOK) continue;
        int found = -1;
        for (NSUInteger j = 0; j < cands.count; j++) if ([cands[j][@"vmaddr"] unsignedLongValue] == head) { found = (int)j; break; }
        if (found < 0) { [cands addObject:[NSMutableDictionary dictionaryWithDictionary:@{@"vmaddr": @(head), @"score": @0, @"calls": @0}]]; found = (int)cands.count - 1; }
        NSMutableDictionary *cd = cands[found];
        cd[@"calls"] = @([cd[@"calls"] intValue] + 1);
        const char *s = skStubNames[callSKIdx[i]];
        int sc = [cd[@"score"] intValue];
        if (strstr(s, "currentEntitlements")) sc += 5;
        else if (strstr(s, "9productID")) sc += 3;
        else if (strstr(s, "7updates")) sc += 2;
        else if (strstr(s, "12TransactionsVMa")) sc += 2;
        else if (strstr(s, "8products3for")) sc += 2;
        else if (strstr(s, "8purchase7")) sc += 1;
        else if (strstr(s, "6finish") || strstr(s, "requestReview")) sc -= 1;
        cd[@"score"] = @(sc);
    }
    if (!cands.count) F8V2_BAIL("prologue-own");
    [cands sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        int d = [b[@"score"] intValue] - [a[@"score"] intValue];
        if (d) return d < 0 ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"calls"] intValue] <= [b[@"calls"] intValue] ? NSOrderedAscending : NSOrderedDescending;  // 并列时 calls 少的在前(判定函数调用点少, UI 函数调用点多)
    }];

    // v2.58.65: sk2ver 判别点扫描已删 — 用户定案(实机三轮零作用: 空流时循环体
    //   不执行, NOP 全空转; 真正解锁的是 sk2pro/sk2get 两个代码 patch 点)。
    //   "事务流验证型"概念随之废除, 不再出现在侦查判决/卡片文案。
    NSMutableArray *sk2pts = [NSMutableArray array];

    // =====================================================================
    // sk2pro (v2.58.52): isPro 写入点 — dbg_54 定谳: 空流时判别点循环体
    //   不执行, 恒 verified NOP 全部空转; 真 gate = 流后汇总的 _isPro 写入。
    //   定位链(侦查读内存, patch 改磁盘字节 — 与 F8v2/F10 同体系, 零 hook):
    //   "Pro state changed" oslog 串 → 运行时解析 __const fmt 槽(值==串abs)
    //   → 磁盘扫 adrp+add 引用槽的 os_log 调用点 → 回溯 strb 写入 + 其前
    //   movz wN,#0 定值 → 点位=movz, patch=movz wN,#1。
    // =====================================================================
    {
        // v2.58.68: 词表驱动(用户纠偏: "都是 sk2 类型, 换个 app 就识别不对? 硬编码特征了?")
        //   —— 旧版门 = 单个字面串(只有特定 app 有) → 换 app 整块死。
        //   实测三样本: 目标 1 命中 / 另两个 0 —— 单串门 = 过度拟合。
        //   改为: __cstring 扫"状态变更播报"语义族(oslog 记录状态翻转) → 取全部命中,
        //   逐个走同一条定位链。词表覆盖 pro/premium/unlock/entitle/subscri + state/changed。
        static const char *kProTagWords[] = { "pro state", "premium state", "unlock state",
            "entitlement state", "subscription state", "purchase state", "pro status",
            "ispro", "pro unlocked", "pro enabled", "premium unlocked", "pro active", "unlock state" };
        const int nProTagWords = (int)(sizeof(kProTagWords) / sizeof(kProTagWords[0]));
        // 收集全部命中串(去重) — 一句 app 可能有多个状态播报点
        uint64_t tagOffs[8]; int nTag = 0;
        for (uint64_t i = 0; i + 6 <= binLen && nTag < 8; i++) {
            // 只看串起点(前一字节非可打印 = 串边界)
            if (i && bd[i - 1] >= 0x20 && bd[i - 1] < 0x7f) continue;
            char lowbuf[96]; int bl = 0;
            while (bl < 95 && i + bl < binLen && bd[i + bl] >= 0x20 && bd[i + bl] < 0x7f) { lowbuf[bl] = (char)tolower(bd[i + bl]); bl++; }
            lowbuf[bl] = 0;
            if (bl < 6 || bl > 94) continue;
            int hit = 0;
            for (int w = 0; w < nProTagWords; w++) {
                const char *wp = strstr(lowbuf, kProTagWords[w]);
                if (!wp) continue;
                // v2.58.68: 词边界门 — 防 "ispro" 命中 Foundation 的 "isProxy"/JS "isPromise"
                //   (实测 WorkingCopy/Uncover 各 1-4 条纯噪声, 全是这个子串撞的)
                char after = wp[strlen(kProTagWords[w])];
                if (after && after != ' ' && after != ':' && after != '.' && after != '_' && after != '+' ) continue;
                hit = 1; break;
            }
            if (!hit) continue;
            // 排除: URL / 本地化文案段 / 非播报串
            if (strstr(lowbuf, "http") || strstr(lowbuf, "://")) continue;
            // v2.58.68: oslog 播报串门 — 必须含格式符(%…)或 ": "(状态播报形态)。
            //   纯文案(本地化 key/反射串如 _isPro/HostLog Pro unlocked)不是 os_log fmt 槽,
            //   收进来只会增加无效 const-slot 扫描轮次。
            if (!strchr(lowbuf, '%') && !strstr(lowbuf, ": ")) continue;
            uint64_t dup = 0;
            for (int d = 0; d < nTag; d++) if (tagOffs[d] == i) { dup = 1; break; }
            if (dup) continue;
            tagOffs[nTag++] = i;
        }
        mfLog(@"[f8v2] sk2pro: 状态播报串词表命中=%d 个(通用, 非单串硬编码)", nTag);
        for (int ti = 0; ti < nTag; ti++) {
            const uint8_t *strHit = bd + tagOffs[ti];
            const char *tagStr = (const char *)strHit;
            uint64_t strVM = baseVM + (uint64_t)(strHit - bd);
            const char *rs = (const char *)((uintptr_t)strVM + (uintptr_t)slide);
            if (strncmp(rs, tagStr, 8) != 0) continue;   // 运行时映射校验(串头 8 字节)
                uint64_t strAbs = (uintptr_t)rs;
                // v2.58.54: 两法合并 — ①槽值法加 PAC 掩码(dyld fixup 阶段可写
                //   __TEXT 数据, 槽值=目标指针+PAC 高位; 2.58.52 精确比较漏了 PAC)
                //   ②指令对法保留兜底。任一命中即 os_log 调用点。
                int nPair = 0;
                {
                    const uint64_t kPacMask = 0x0000000FFFFFFFFFULL;   // 用户态 36 位地址
                    uint64_t pacAbs = strAbs & kPacMask;
                    for (int s2 = 0; s2 < nConstSec; s2++) {
                        uint64_t sv = constSecVM[s2];
                        for (uint64_t o = 0; o + 8 <= constSecSize[s2]; o += 8) {
                            uint64_t v = *(const uint64_t *)((uintptr_t)sv + (uintptr_t)slide + o);
                            if ((v & kPacMask) != pacAbs) continue;
                            uint64_t slot = sv + o;
                            mfLog(@"[f8v2] sk2pro: fmt槽 @%#llx → Pro串 (PAC=%#llx)", (unsigned long long)slot, v);
                            // 磁盘扫引用该槽的 adrp+add 对(os_log 调用点)
                            for (uint64_t off = 0; off + 8 <= textSize; off += 4) {
                                uint32_t i1 = *(const uint32_t *)(bd + textFileOff + off);
                                uint32_t i2 = *(const uint32_t *)(bd + textFileOff + off + 4);
                                if ((i1 & 0x9F000000) != 0x90000000) continue;
                                if ((i2 & 0xFFC00000) != 0x91000000) continue;
                                int64_t imm = (int64_t)((((i1 >> 5) & 0x7FFFF) << 2) | ((i1 >> 29) & 3));
                                if (imm & (1 << 20)) imm -= (int64_t)(1 << 21);
                                uint64_t page = ((textVM + off) & ~0xFFFULL) + ((uint64_t)imm << 12);
                                uint32_t rd = (i2 >> 5) & 0x1F, rn = i2 & 0x1F;
                                if (rd != rn) continue;
                                if (page + (uint32_t)((i2 >> 10) & 0xFFF) != slot) continue;
                                uint64_t ref = textVM + off;
                                nPair++;
                                mfLog(@"[f8v2] sk2pro: Pro串引用 @%#llx", (unsigned long long)ref);
                                // v2.58.56: 真判定形态(本地静态验证实锤, dbg_58 转储):
                                //   数据源装载 = ldr xT,[xK,#imm] + cmp xT,#0 + cset wS,cond
                                //   (0x1000a2f68: ldr x23,[x8,#0x10]; cmp x23,#0; cset w24,ne)
                                //   "权益记录存在?=ne" → 经 eor 比较后 cset+strb 写回 _isPro。
                                //   patch = ldr → movz xT,#1(记录恒存在 → isPro 恒真)。
                                //   旧版向前回溯 movz#0+strb 是旧值形态, 方向错 — 已废。
                                uint64_t winLo = ref >= textVM + 0x500 ? ref - 0x500 : textVM;
                                uint64_t winHi = ref + 0x500;
                                if (winHi > textVM + textSize) winHi = textVM + textSize;
                                int nPatA = 0;
                                for (uint64_t a3 = winLo; a3 + 12 <= winHi; a3 += 4) {
                                    uint64_t o3 = a3 - textVM;
                                    uint32_t w1 = *(const uint32_t *)(bd + textFileOff + o3);
                                    if ((w1 & 0xFFC00000) != 0xF9400000) continue;      // ldr xT,[xK,#imm12]
                                    uint32_t T1 = w1 & 0x1F;
                                    if (T1 == 31) continue;
                                    uint32_t w2 = *(const uint32_t *)(bd + textFileOff + o3 + 4);
                                    if ((w2 & 0xFFFFFC1F) != 0xF100001F) continue;      // cmp xT,#0
                                    if (((w2 >> 5) & 0x1F) != T1) continue;
                                    uint32_t w3 = *(const uint32_t *)(bd + textFileOff + o3 + 8);
                                    if ((w3 & 0xFFFF0FE0) != 0x1A9F07E0) continue;      // cset wS,cond
                                    uint32_t S1 = w3 & 0x1F;
                                    BOOL dup2 = NO;
                                    for (NSDictionary *sp in sk2pts)
                                        if ([sp[@"vmaddr"] unsignedLongLongValue] == a3) { dup2 = YES; break; }
                                    if (dup2) continue;
                                    uint32_t movNew = 0xD2800000u | (1u << 5) | T1;     // movz xT,#1
                                    nPatA++;
                                    [sk2pts addObject:@{
                                        @"img": mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main",
                                        @"sym": [NSString stringWithFormat:@"sk2pro@%#llx", (unsigned long long)(a3 - textVM)],
                                        @"vmaddr": @(a3),
                                        @"slide": @((long)slide),
                                        @"score": @(96),
                                        @"calls": @(0),
                                        @"shape": @"sk2pro",
                                        @"kind": @"sk2pro",
                                        @"old": mfLeHex(w1),
                                        @"new": mfLeHex(movNew),
                                    }];
                                    mfLog(@"[f8v2] ★sk2pro @%#llx (ldr x%u→movz x%u,#1, cset w%u, oslog@%#llx)", (unsigned long long)a3, T1, T1, S1, (unsigned long long)ref);
                                }
                                if (!nPatA) {
                                    NSMutableString *ds = [NSMutableString string];
                                    for (int64_t b3 = 0x40; b3 >= 4; b3 -= 4) {
                                        if (off < (uint64_t)b3) continue;
                                        uint32_t w = *(const uint32_t *)(bd + textFileOff + off - b3);
                                        [ds appendFormat:@" %#llx=%08x", (unsigned long long)(textVM + off - b3), w];
                                    }
                                    mfLog(@"[f8v2] sk2pro: ldr+cmp+cset 未命中(窗口±0x500) @%#llx |%s", (unsigned long long)ref, ds.UTF8String);
                                }
                            }
                        }
                    }
                }
                // ② 指令对兜底(运行时立即数已被 dyld 改写为直指串时命中)
                for (uint64_t off = 0; off + 8 <= textSize; off += 4) {
                    uint32_t i1 = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off);
                    uint32_t i2 = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off + 4);
                    if ((i1 & 0x9F000000) != 0x90000000) continue;      // adrp
                    if ((i2 & 0xFFC00000) != 0x91000000) continue;      // add Xd,Xn,#imm12
                    int64_t imm = (int64_t)((((i1 >> 5) & 0x7FFFF) << 2) | ((i1 >> 29) & 3));
                    if (imm & (1 << 20)) imm -= (int64_t)(1 << 21);
                    // v2.58.55: 页基址必须含 slide — dyld 改写的是运行时立即数,
                    //   目标页 = (运行时地址 & ~0xfff) + imm<<12。旧代码用无 slide 的
                    //   textVM+off 当页基 → 解码出的目标永远比 strAbs 少一个 slide → 0 命中
                    uint64_t page = (((uintptr_t)textVM + (uintptr_t)slide + off) & ~0xFFFULL) + ((uint64_t)imm << 12);
                    uint32_t rd = (i2 >> 5) & 0x1F, rn = i2 & 0x1F;
                    if (rd != rn) continue;
                    uint64_t tgt = page + (uint32_t)((i2 >> 10) & 0xFFF);
                    if (tgt != strAbs) continue;
                    nPair++;
                    uint64_t ref = textVM + off;   // os_log 调用点(adrp)
                    mfLog(@"[f8v2] sk2pro: Pro串引用 @%#llx", (unsigned long long)ref);
                    // v2.58.57: 与 ① 同判据 — 真判定形态 = 数据源装载三连
                    //   ldr xT,[xK,#imm] + cmp xT,#0 + cset wS,cond @0x1000a2f68 实锤。
                    //   patch = ldr → movz xT,#1(记录恒存在 → isPro 恒真)。
                    //   (旧 movz#0+strb 回溯是旧值形态, 方向错 — dbg_60 仍 0 命中, 已废)
                    uint64_t winLo = ref >= textVM + 0x500 ? ref - 0x500 : textVM;
                    uint64_t winHi = ref + 0x500;
                    if (winHi > textVM + textSize) winHi = textVM + textSize;
                    int nPatB = 0;
                    for (uint64_t a3 = winLo; a3 + 12 <= winHi; a3 += 4) {
                        uint64_t o3 = a3 - textVM;
                        uint32_t w1 = *(const uint32_t *)(bd + textFileOff + o3);
                        if ((w1 & 0xFFC00000) != 0xF9400000) continue;      // ldr xT,[xK,#imm12]
                        uint32_t T1 = w1 & 0x1F;
                        if (T1 == 31) continue;
                        uint32_t w2 = *(const uint32_t *)(bd + textFileOff + o3 + 4);
                        if ((w2 & 0xFFFFFC1F) != 0xF100001F) continue;      // cmp xT,#0
                        if (((w2 >> 5) & 0x1F) != T1) continue;
                        uint32_t w3 = *(const uint32_t *)(bd + textFileOff + o3 + 8);
                        if ((w3 & 0xFFFF0FE0) != 0x1A9F07E0) continue;      // cset wS,cond
                        uint32_t S1 = w3 & 0x1F;
                        BOOL dup2 = NO;
                        for (NSDictionary *sp in sk2pts)
                            if ([sp[@"vmaddr"] unsignedLongLongValue] == a3) { dup2 = YES; break; }
                        if (dup2) continue;
                        uint32_t movNew = 0xD2800000u | (1u << 5) | T1;     // movz xT,#1
                        nPatB++;
                        [sk2pts addObject:@{
                            @"img": mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main",
                            @"sym": [NSString stringWithFormat:@"sk2pro@%#llx", (unsigned long long)(a3 - textVM)],
                            @"vmaddr": @(a3),
                            @"slide": @((long)slide),
                            @"score": @(96),
                            @"calls": @(0),
                            @"shape": @"sk2pro",
                            @"kind": @"sk2pro",
                            @"old": mfLeHex(w1),
                            @"new": mfLeHex(movNew),
                        }];
                        mfLog(@"[f8v2] ★sk2pro @%#llx (ldr x%u→movz x%u,#1, cset w%u, oslog@%#llx)", (unsigned long long)a3, T1, T1, S1, (unsigned long long)ref);
                    }
                    if (!nPatB) {
                        NSMutableString *ds = [NSMutableString string];
                        for (int64_t b3 = 0x40; b3 >= 4; b3 -= 4) {
                            if (off < (uint64_t)b3) continue;
                            uint32_t w = *(const uint32_t *)(bd + textFileOff + off - b3);
                            [ds appendFormat:@" %#llx=%08x", (unsigned long long)(textVM + off - b3), w];
                        }
                        mfLog(@"[f8v2] sk2pro: ldr+cmp+cset 未命中(窗口±0x500) @%#llx |%s", (unsigned long long)ref, ds.UTF8String);
                    }
                }
                NSUInteger nPro = 0;
                for (NSDictionary *sp in sk2pts) if ([sp[@"shape"] isEqualToString:@"sk2pro"]) nPro++;
                mfLog(@"[f8v2] sk2pro: Pro串引用=%d 个 → isPro 写入点=%lu 个", nPair, (unsigned long)nPro);
                // v2.58.62: 扩展链 — isPro 是 @Observable 存储属性, refresh 执行与否
                //   取决于运行时(未购买态可能不跑, dbg_65 sk2diag=nil 实锤)。
                //   读侧才是 UI 真入口: 3 个 @Observable getter(ldrb w0,[xN,#0x10] 尾)
                //   → 恒 true。由 UD 镜像 key 串定位确认偏移(防布局漂移)。
                {
                    // v2.58.68: UD 镜像 key 也去硬编码(旧版写死单个目标 key;
                    //   换 app 永远 0 命中)。改为通用: 扫"点分命名 + 权益语义族"的 key 串,
                    //   取命中数最多的族作布局锚(镜像 key 是 UI 读侧的真实 key)。
                    static const char *kProKeyWords[] = { "ispro", "entitle", "isvip", "premium",
                        "license", "purchase", "subscri", "pro.v", "unlock" };
                    const int nProKeyWords = (int)(sizeof(kProKeyWords) / sizeof(kProKeyWords[0]));
                    int  nKeyHit = 0;
                    uint64_t keyAnchor = 0;
                    for (uint64_t i = 0; i + 8 <= binLen; i++) {
                        if (i && bd[i - 1] >= 0x20 && bd[i - 1] < 0x7f) continue;   // 串边界
                        // 点分 key 形态: 含 '.' 且字符集 [A-Za-z0-9._-]
                        int bl = 0; BOOL dotted = NO, bad = NO;
                        char lowb[160];
                        while (bl < 159 && i + bl < binLen) {
                            uint8_t c = bd[i + bl];
                            if (c == 0) break;
                            if (c == '.') dotted = YES;
                            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                  (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) { bad = YES; break; }
                            lowb[bl] = (char)tolower(c); bl++;
                        }
                        lowb[bl] = 0;
                        if (bad || !dotted || bl < 8 || bl > 158) continue;
                        // 必须像 UD key(root 段 + 语义段)
                        for (int w = 0; w < nProKeyWords; w++) {
                            if (strstr(lowb, kProKeyWords[w])) {
                                if (!nKeyHit) keyAnchor = baseVM + i;
                                nKeyHit++;
                                break;
                            }
                        }
                        if (nKeyHit >= 4) break;
                    }
                    if (nKeyHit) {
                        mfLog(@"[f8v2] sk2pro: UD镜像key 词表命中=%d 个 → 布局锚 @%#llx(通用, 非单串)", nKeyHit, (unsigned long long)keyAnchor);
                    }
                    // 读侧 getter 扫描: ldrb w0,[xN,#0x10] + 8 条内 ret = Bool getter 尾。
                    // v2.58.62: keypath 锚定 — 只收引用了 refresh 函数 keypath 集的 getter
                    //   (排除其他类 0x10 偏移 Bool getter 误报: 0x10007fb2c 无 bl 裸访问器,
                    //    0x10000aa1c 引用的 keypath 不在集内 — 静态实证均已排除)
                    uint64_t kpC[12]; int nKp = 0;
                    for (NSDictionary *sp in sk2pts) {
                        if (![sp[@"shape"] isEqualToString:@"sk2pro"]) continue;
                        uint64_t pt = [sp[@"vmaddr"] unsignedLongLongValue];
                        uint64_t lo4 = pt > 0x800 ? pt - 0x800 : textVM;
                        uint64_t hi4 = pt + 0x800; if (hi4 > textVM + textSize) hi4 = textVM + textSize;
                        for (uint64_t a4 = lo4; a4 + 8 <= hi4; a4 += 4) {
                            uint32_t i1 = *(const uint32_t *)(bd + textFileOff + (a4 - textVM));
                            if ((i1 & 0x9F000000) != 0x90000000) continue;
                            uint32_t i2 = *(const uint32_t *)(bd + textFileOff + (a4 - textVM) + 4);
                            if ((i2 & 0xFFC00000) != 0x91000000) continue;
                            if (((i2 >> 5) & 0x1F) != (i2 & 0x1F)) continue;
                            int64_t imm = (int64_t)((((i1 >> 5) & 0x7FFFF) << 2) | ((i1 >> 29) & 3));
                            if (imm & (1 << 20)) imm -= (int64_t)(1 << 21);
                            uint64_t tgt = (a4 & ~0xFFFULL) + ((uint64_t)imm << 12) + (uint32_t)((i2 >> 10) & 0xFFF);
                            for (int s3 = 0; s3 < nConstSec; s3++) {
                                if (tgt < constSecVM[s3] || tgt >= constSecVM[s3] + constSecSize[s3]) continue;
                                BOOL seen = NO;
                                for (int k = 0; k < nKp; k++) if (kpC[k] == tgt) { seen = YES; break; }
                                if (!seen && nKp < 12) kpC[nKp++] = tgt;
                                break;
                            }
                        }
                    }
                    mfLog(@"[f8v2] sk2pro: keypath 锚定集=%d 个", nKp);
                    int nGet = 0;
                    if (nKp > 0) for (uint64_t off = 0; off + 0x24 <= textSize; off += 4) {
                        uint32_t w1 = *(const uint32_t *)(bd + textFileOff + off);
                        if ((w1 & 0xFFC00000) != 0x39400000) continue;      // ldrb w?, [x?, #imm]
                        if ((w1 & 0x1F) != 0) continue;                      // 只收 w0
                        // v2.58.68: 偏移不写死(旧版固定 0x10 = HostLog 的 _isPro 槽)。
                        //   Bool getter 槽偏移由布局决定 — 收所有偏移, 靠 keypath 锚定
                        //   与"短函数体 + ldrb w0 + ret"形态过滤(下方 anchored 门)。
                        uint32_t ldOff = (w1 >> 10) & 0xFFF;
                        if (ldOff == 0 || ldOff > 0x400) continue;          // 合理标量槽范围
                        BOOL hasRet = NO;
                        for (uint64_t k = off + 4; k <= off + 0x20 && k + 4 <= textSize; k += 4)
                            if (*(const uint32_t *)(bd + textFileOff + k) == 0xD65F03C0) { hasRet = YES; break; }
                        if (!hasRet) continue;
                        BOOL anchored = NO;
                        uint64_t lo5 = off >= 0x100 ? off - 0x100 : 0;
                        for (uint64_t a5 = lo5; a5 + 8 <= off && !anchored; a5 += 4) {
                            uint32_t j1 = *(const uint32_t *)(bd + textFileOff + a5);
                            if ((j1 & 0x9F000000) != 0x90000000) continue;
                            uint32_t j2 = *(const uint32_t *)(bd + textFileOff + a5 + 4);
                            if ((j2 & 0xFFC00000) != 0x91000000) continue;
                            if (((j2 >> 5) & 0x1F) != (j2 & 0x1F)) continue;
                            int64_t imm5 = (int64_t)((((j1 >> 5) & 0x7FFFF) << 2) | ((j1 >> 29) & 3));
                            if (imm5 & (1 << 20)) imm5 -= (int64_t)(1 << 21);
                            uint64_t t5 = ((textVM + a5) & ~0xFFFULL) + ((uint64_t)imm5 << 12) + (uint32_t)((j2 >> 10) & 0xFFF);
                            for (int k = 0; k < nKp; k++) if (kpC[k] == t5) { anchored = YES; break; }
                        }
                        if (!anchored) continue;
                        BOOL dup3 = NO;
                        for (NSDictionary *sp in sk2pts)
                            if ([sp[@"vmaddr"] unsignedLongLongValue] == textVM + off) { dup3 = YES; break; }
                        if (dup3) continue;
                        nGet++;
                        uint32_t movOne = 0x52800020u;   // mov w0,#1
                        [sk2pts addObject:@{
                            @"img": mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main",
                            @"sym": [NSString stringWithFormat:@"sk2get@%#llx", (unsigned long long)off],
                            @"vmaddr": @(textVM + off),
                            @"slide": @((long)slide),
                            @"score": @(97),
                            @"calls": @(0),
                            @"shape": @"sk2get",
                            @"kind": @"sk2get",
                            @"old": mfLeHex(w1),
                            @"new": mfLeHex(movOne),
                        }];
                        mfLog(@"[f8v2] ★sk2get @%#llx (ldrb w0,[xN,#0x10]→mov w0,#1, UI读侧恒真)", (unsigned long long)(textVM + off));
                    }
                    mfLog(@"[f8v2] sk2pro: getter 读侧点位=%d 个(UI 直读 _isPro 槽)", nGet);
                }
            }
        }


    // =====================================================================
    // sk2br (v2.58.78): 分支粒度判定点 — 打"Pro 门"的分支决策, 不砍函数头。
    //   动机(dbg_79): 真点 0x1004a080c/0x100c053ac 函数头 mov w0,#1;ret 全空转 —
    //   多返回路径的大函数里, 函数头短路 ≠ "Pro 有效"。
    //   算法(零 SKU 硬编码, 只用形态门):
    //     ① __TEXT 线性扫 SKU 形态串(全小写+含点, 词含 pro/vip/premium/subscri)
    //     ② adrp+add 引用 → 归属引用函数(≤16)
    //     ③ 函数内扫条件分支(b.cond/tbz/tbnz/cbz/cbnz)统计靶频次
    //     ④ M = fan-in ≥2 的最大靶(> 函数头) = "命中/继续" 汇聚点
    //     ⑤ escape = 条件分支中 fall-through(pc+4)==M 的那条(即"未命中→逃逸")
    //        patch = NOP(4B) → 恒走 M(matched 路径)
    //   实测(bplayer): 0x1004a080c escape=0x1004a09fc→M=0x1004a0a00;
    //                   0x100c053ac escape=0x100c05a64→M=0x100c05a68(4 分支汇聚)
    // =====================================================================
    {
        // v2.58.79: SKU 串在 __cstring(不是 __text!) — dbg_81 定谳:
        //   旧实现扫 __text → SKU串=0 → 块静默跳过。改用 LC 拿到的 __cstring 范围。
        uint64_t skuVM[64]; int nSku2 = 0;
        for (uint64_t o2 = 0; o2 + 8 < cstrSize && nSku2 < 64; o2++) {
            if (bd[cstrFileOff + o2] != 0) continue;
            const char *sp = (const char *)(bd + cstrFileOff + o2 + 1);
            size_t L = strnlen(sp, 65);
            if (L < 5 || L > 64) continue;
            if (!memchr(sp, '.', L)) continue;
            int bad = 0, hasUpper = 0;
            for (size_t k = 0; k < L; k++) {
                char c = sp[k];
                if (c >= 'A' && c <= 'Z') { hasUpper = 1; break; }
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) { bad = 1; break; }
            }
            if (bad || hasUpper) continue;
            if (!memmem(sp, L, "pro", 3) && !memmem(sp, L, "vip", 3) &&
                !memmem(sp, L, "premium", 7) && !memmem(sp, L, "subscri", 7)) continue;
            skuVM[nSku2++] = cstrVM + o2 + 1;
        }
        if (nSku2) {
            uint64_t refFn[16]; int nRefFn = 0;
            for (uint64_t off = 0; off + 8 < textSize && nRefFn < 16; off += 4) {
                uint32_t w1 = *(const uint32_t *)(bd + textFileOff + off);
                if ((w1 & 0x9F000000) != 0x90000000) continue;
                uint32_t w2 = *(const uint32_t *)(bd + textFileOff + off + 4);
                if ((w2 & 0xFFC00000) != 0x91000000) continue;
                int64_t immlo = (w1 >> 29) & 3, immhi = (w1 >> 5) & 0x7FFFF;
                int64_t imm = (immhi << 2) | immlo;
                if (imm & (1 << 20)) imm -= (1 << 21);
                uint64_t page = ((textVM + off) & ~0xFFFULL) + ((uint64_t)imm << 12);
                uint64_t tgt = page + ((w2 >> 10) & 0xFFF);
                BOOL isSku = NO;
                for (int k = 0; k < nSku2; k++) if (skuVM[k] == tgt) { isSku = YES; break; }
                if (!isSku) continue;
                uint64_t h2 = 0;
                for (uint64_t back = 0; back < 0x10000 && off >= back + 4; back += 4) {
                    uint32_t q = *(const uint32_t *)(bd + textFileOff + off - back);
                    if (q == 0xD503237F || ((q & 0x7FC00000) == 0x29800000 && ((q >> 5) & 0x1F) == 31) ||
                        ((q & 0xFFC003FF) == 0xD10003FF && ((q >> 10) & 0xFFF))) { h2 = textVM + off - back; break; }
                }
                if (!h2) continue;
                BOOL dup2 = NO;
                for (int k = 0; k < nRefFn; k++) if (refFn[k] == h2) { dup2 = YES; break; }
                if (!dup2 && nRefFn < 16) refFn[nRefFn++] = h2;
            }
            int nBr = 0;
            for (int f = 0; f < nRefFn; f++) {
                uint64_t h = refFn[f];
                uint64_t tgtBuf[128]; int cntBuf[128]; int nT = 0;
                for (uint64_t o = 0; o < 0x3000; o += 4) {
                    uint64_t a = h + o;
                    if (a + 4 > textVM + textSize) break;
                    uint32_t w = *(const uint32_t *)(bd + textFileOff + (a - textVM));
                    if (w == 0xD65F03C0 && o > 0x20) break;
                    uint64_t t = 0;
                    if ((w & 0xFF000010) == 0x54000000) {
                        int64_t im = (w >> 5) & 0x7FFFF; if (im & 0x40000) im -= 0x80000;
                        t = a + im * 4;
                    } else if (((w >> 25) & 0x3F) == 0b011011) {
                        int64_t im = (w >> 5) & 0x3FFF; if (im & 0x2000) im -= 0x4000;
                        t = a + im * 4;
                    } else if ((w & 0x7F000000) == 0x34000000) {
                        int64_t im = (w >> 5) & 0x7FFFF; if (im & 0x40000) im -= 0x80000;
                        t = a + im * 4;
                    } else continue;
                    if (t <= h) continue;
                    int idx = -1;
                    for (int k = 0; k < nT; k++) if (tgtBuf[k] == t) { idx = k; break; }
                    if (idx < 0) { if (nT >= 128) continue; idx = nT++; tgtBuf[idx] = t; cntBuf[idx] = 0; }
                    cntBuf[idx]++;
                }
                uint64_t M = 0; int best = 0;
                for (int k = 0; k < nT; k++) if (cntBuf[k] > best) { best = cntBuf[k]; M = tgtBuf[k]; }
                if (best < 2) continue;
                uint64_t esc = 0; uint32_t escW = 0;
                for (uint64_t o = 0; o < 0x3000; o += 4) {
                    uint64_t a = h + o;
                    if (a + 4 > textVM + textSize) break;
                    uint32_t w = *(const uint32_t *)(bd + textFileOff + (a - textVM));
                    uint64_t t = 0; BOOL isBr = NO;
                    if ((w & 0xFF000010) == 0x54000000) {
                        int64_t im = (w >> 5) & 0x7FFFF; if (im & 0x40000) im -= 0x80000;
                        t = a + im * 4; isBr = YES;
                    } else if (((w >> 25) & 0x3F) == 0b011011) {
                        int64_t im = (w >> 5) & 0x3FFF; if (im & 0x2000) im -= 0x4000;
                        t = a + im * 4; isBr = YES;
                    } else if ((w & 0x7F000000) == 0x34000000) {
                        int64_t im = (w >> 5) & 0x7FFFF; if (im & 0x40000) im -= 0x80000;
                        t = a + im * 4; isBr = YES;
                    }
                    if (!isBr || t == M) continue;
                    if (a + 4 == M) { esc = a; escW = w; break; }
                }
                if (!esc) continue;
                nBr++;
                [sk2pts addObject:@{
                    @"img": mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main",
                    @"sym": [NSString stringWithFormat:@"sk2br@%#llx", (unsigned long long)(esc - textVM)],
                    @"vmaddr": @(esc),
                    @"slide": @((long)slide),
                    @"score": @(94),
                    @"calls": @(0),
                    @"shape": @"sk2br",
                    @"kind": @"sk2br",
                    @"old": mfLeHex(escW),
                    @"new": mfLeHex(0xD503201Fu),   // nop → fall through 到汇聚点
                }];
                mfLog(@"[f8v2] ★sk2br @%#llx (Pro门分支: 逃逸→NOP, 恒走汇聚点 %#llx, fan=%d)",
                      (unsigned long long)esc, (unsigned long long)M, best);
            }
            mfLog(@"[f8v2] sk2br: SKU串=%d 引用函数=%d 门分支点=%d 个", nSku2, nRefFn, nBr);
        } else {
            mfLog(@"[f8v2] sk2br: __cstring 区(%#llx+%#llx) 无 SKU 形态串", cstrVM, cstrSize);
        }
    }

    // =====================================================================
    // sk2vfy (v2.58.114): SK2 权益验证判定点 — C1 路线。
    //   动机(用户定案): SK2 无收据可伪造 — appStoreReceiptURL/transactionReceipt 都是
    //   SK1 机制; SK2 权益源 = Transaction.currentEntitlements → JWS 验签,
    //   本地无有效交易 → 整链恒 false → 只能代码 patch。
    //   判据(通用, 零 app 硬编码; 本地原型 29 候选/9 函数, 目标点全中):
    //     ① 锚点 = 验证类 stub 调用点(vfyStubVM: currentEntitlements/
    //        jwsRepresentation/payloadValue/revocationDate/expirationDate/
    //        updates/makeAsyncIterator/Environment — 符号名来自 LINKEDIT imports 池)
    //     ② 锚点所在函数(向前找序言) = SK2 验证函数
    //     ③ 函数体 ±0x400 内扫 (cmp wT,#1 ; b.cond 前向分支) = "交易有效?"判定
    //   执行: b.cond → NOP, 让"无效"分支失效(fall through 到有效路径)。
    //   隔离: 新 shape sk2vfy(独立 sym 前缀 + 独立执行分支), 老 shape 不动。
    // =====================================================================
    {
        int nVfy = 0;
        if (nVfyStub > 0) {
            // ① 找验证 stub 的调用点
            static uint64_t vfyCallPC[256];
            int nVfyCall = 0;
            for (uint64_t off = 0; off + 4 <= textSize && nVfyCall < 256; off += 4) {
                uint32_t ins = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off);
                uint32_t op = ins >> 26;
                if (op != 0x25 && op != 0x05) continue;      // bl / b
                int64_t imm = (int64_t)(ins & 0x3FFFFFF);
                if (imm & (1 << 25)) imm -= (int64_t)(1 << 26);
                uint64_t tgt = textVM + off + ((uint64_t)imm << 2);
                for (int k = 0; k < nVfyStub; k++)
                    if (vfyStubVM[k] == tgt) { vfyCallPC[nVfyCall++] = textVM + off; break; }
            }
            // ② 调用点所在函数(向前找序言)
            uint64_t vfyFn[64]; int nVfyFn = 0;
            for (int i = 0; i < nVfyCall && nVfyFn < 64; i++) {
                uint64_t pc = vfyCallPC[i];
                for (uint64_t back = 0; back < 0x4000; back += 4) {
                    if (pc < textVM + back) break;
                    uintptr_t ha = (uintptr_t)(pc - back) + (uintptr_t)slide;
                    uint32_t q = *(const uint32_t *)ha;
                    BOOL isHead = NO;
                    if (q == 0xD503237F) isHead = YES;
                    else if ((q & 0x7FC00000) == 0x29800000 && ((q >> 5) & 0x1F) == 31) isHead = YES;
                    else if ((q & 0xFFC003FF) == 0xD10003FF && ((q >> 10) & 0xFFF)) isHead = YES;
                    else if (q == 0xB24003BD) isHead = YES;      // async 序言 orr x29,x29,#0x1
                    if (isHead) {
                        uint64_t h = pc - back;
                        BOOL dup = NO;
                        for (int j = 0; j < nVfyFn; j++) if (vfyFn[j] == h) { dup = YES; break; }
                        if (!dup) vfyFn[nVfyFn++] = h;
                        break;
                    }
                }
            }
            // ③ 验证函数体内 ±0x400 扫 (cmp wT,#1 ; b.cond)
            for (int fi = 0; fi < nVfyFn; fi++) {
                uint64_t fh = vfyFn[fi];
                uint64_t lo = (fh > textVM + 0x400) ? fh - 0x400 : textVM;
                uint64_t hi = fh + 0x1000;
                if (hi > textVM + textSize) hi = textVM + textSize;
                for (uint64_t p = lo; p + 8 <= hi; p += 4) {
                    uint32_t w1v = *(const uint32_t *)((uintptr_t)p + (uintptr_t)slide);
                    // b.cond: 0x54000000 mask 0xFF000010
                    if ((w1v & 0xFF000010) != 0x54000000) continue;
                    uint32_t cond = w1v & 0xF;
                    if (cond != 1 && cond != 0) continue;        // 只要 b.ne / b.eq
                    int32_t im19 = (int32_t)((w1v >> 5) & 0x7FFFF);
                    if (im19 & (1 << 18)) im19 -= (1 << 19);
                    uint64_t bTgt = p + ((uint64_t)im19 << 2);
                    if (bTgt <= p) continue;                     // 只收前向分支
                    // 前 3 条找 cmp wT,#1
                    uint64_t cPos = 0; BOOL cOK = NO;
                    for (int k = 1; k <= 3; k++) {
                        if (p < textVM + (uint64_t)k * 4) break;
                        uint32_t w2v = *(const uint32_t *)((uintptr_t)(p - k * 4) + (uintptr_t)slide);
                        if ((w2v & 0xFFFFFC1F) == 0x7100041F) { cPos = p - k * 4; cOK = YES; break; }
                    }
                    if (!cOK) continue;
                    // v2.58.116: "真门形态"判定 — 用户实测(dbg_107)三个点亮点的形态:
                    //   ldrb wT,[xN,#tagOff]      ← 读 Optional 判别式
                    //   cmp  wT,#1
                    //   b.ne → nil 路径            ← 门
                    //   ── fall-through ──
                    //   ldp/ldr 从同基址加载值     ← 取 Optional payload
                    //   bl _swift_bridgeObjectRetain  ← 持有该值(引用类型)
                    //   这不是普通 Optional 解包(普通解包不 retain); 是"有值则取出并使用"。
                    //   NOP 后强制走有值路径 → 权益链认为字段存在。
                    //   本地验证(bplayer): 20 个门里只有这 3 个命中, 其余 17 个全 False。
                    //   注: 判据只调 score(不增删点位), 真门排前。
                    uint32_t tagBase = 31; uint32_t tagOff = 0xFFFFFFFF;
                    for (int k = 1; k <= 3; k++) {
                        if (p < textVM + (uint64_t)k * 4) break;
                        uint32_t wq = *(const uint32_t *)((uintptr_t)(p - k * 4) + (uintptr_t)slide);
                        if ((wq & 0xFFC00000) == 0x39400000) { tagBase = (wq >> 5) & 0x1F; tagOff = (wq >> 10) & 0xFFF; break; }
                    }
                    BOOL isRealGate = NO;
                    if (tagBase != 31) {
                        // fall-through 8 条内: 同基址加载值
                        BOOL valLoad = NO;
                        for (int k = 1; k <= 8; k++) {
                            uint32_t wq = *(const uint32_t *)((uintptr_t)(p + (uint64_t)k * 4) + (uintptr_t)slide);
                            uint32_t rn = (wq >> 5) & 0x1F;
                            if (rn != tagBase) continue;
                            if ((wq & 0xFFC00000) == 0xA9400000 ||   // ldp (64-bit)
                                (wq & 0xFFC00000) == 0xA9C00000 ||   // ldp (pre-index)
                                (wq & 0xFFC00000) == 0xF9400000) {   // ldr
                                valLoad = YES; break;
                            }
                        }
                        // fall-through 14 条内: bl _swift_bridgeObjectRetain
                        BOOL doRetain = NO;
                        if (valLoad) {
                            for (int k = 1; k <= 14; k++) {
                                uint32_t wq = *(const uint32_t *)((uintptr_t)(p + (uint64_t)k * 4) + (uintptr_t)slide);
                                if ((wq & 0xFC000000) != 0x94000000) continue;
                                int64_t im2 = (int64_t)(wq & 0x3FFFFFF);
                                if (im2 & (1 << 25)) im2 -= (int64_t)(1 << 26);
                                uint64_t t2 = p + (uint64_t)k * 4 + ((uint64_t)im2 << 2);
                                // v2.58.118: 查 retain stub 小表(走查已按名过滤, 不再受上限截断)
                                for (int sk = 0; sk < nRetainStub; sk++) {
                                    if (retainStubVM[sk] == t2) { doRetain = YES; break; }
                                }
                                if (doRetain) break;
                            }
                        }
                        if (valLoad && doRetain) isRealGate = YES;
                    }
                    // v2.58.123 (dbg_116 定谳): 权益锚定 — 门前 24 条内有 bl 到
                    //   "权益状态" StoreKit API(expirationDate/revocationDate/currentEntitlements/
                    //   AppTransaction.shared), 才是真判定门; 仅 productID/jwsRepresentation
                    //   等展示类 API 不算。实证: target-app 30 门里只有 1 个命中
                    //   (0x102365364: bl expirationDate → cmp w0,#1 → b.ne), 其余 29 个
                    //   是普通 Optional 解包 → 这正是"180 点全不亮"的根因。
                    BOOL entAnchor = NO;
                    if (!isRealGate) {
                        for (int k = 1; k <= 24; k++) {
                            if (p < textVM + (uint64_t)k * 4) break;
                            uint32_t wq = *(const uint32_t *)((uintptr_t)(p - k * 4) + (uintptr_t)slide);
                            if ((wq & 0xFC000000) != 0x94000000) continue;   // bl only
                            int64_t im3 = (int64_t)(wq & 0x3FFFFFF);
                            if (im3 & (1 << 25)) im3 -= (int64_t)(1 << 26);
                            uint64_t t3 = (p - (uint64_t)k * 4) + ((uint64_t)im3 << 2);
                            // 解 stub → 符号名(复用 vfyStubVM 表: 验证类符号已收)
                            for (int vk = 0; vk < nVfyStub; vk++) {
                                if (vfyStubVM[vk] != t3) continue;
                                const char *sn = vfyStubNames[vk] ?: "";
                                // 权益状态类 API(非展示类): expirationDate/revocationDate/currentEntitlements
                                if (strstr(sn, "expirationDate") || strstr(sn, "revocationDate") ||
                                    strstr(sn, "currentEntitlements") || strstr(sn, "AppTransaction")) {
                                    entAnchor = YES;
                                }
                                break;
                            }
                            if (entAnchor) break;
                        }
                    }
                    // v2.58.123: 双守卫检测 — 门前 3 条内有 cbz/cbnz 到同一寄存器(tag 提前判空),
                    //   target-app 形态: ldrb tag → cbz(跳走) → cmp#1 → b.ne。只 NOP b.ne 时
                    //   tag==0 仍被 cbz 拦住 → 必须同时 patch cbz(改 nop 或改 b 到 fall-through)。
                    BOOL dblGuard = NO; uint64_t dblGuardAddr = 0; uint32_t dblGuardOld = 0;
                    {
                        uint32_t tagReg = 0xFFFFFFFF;
                        for (int k = 1; k <= 4; k++) {
                            if (p < textVM + (uint64_t)k * 4) break;
                            uint32_t wq = *(const uint32_t *)((uintptr_t)(p - k * 4) + (uintptr_t)slide);
                            if ((wq & 0xFFC00000) == 0x39400000) { tagReg = (wq >> 0) & 0x1F; break; }
                        }
                        if (tagReg != 0xFFFFFFFF) {
                            for (int k = 1; k <= 4; k++) {
                                if (p < textVM + (uint64_t)k * 4) break;
                                uint32_t wq = *(const uint32_t *)((uintptr_t)(p - k * 4) + (uintptr_t)slide);
                                // v2.58.123 修正: cbz/cbnz 掩码用 0x7F000000(Rt 在 bit0-4,
                                //   旧的 0xFF000010 把 bit4 当固定位 → 检测永远失败)
                                if ((wq & 0x7F000000) == 0x34000000 && ((wq >> 0) & 0x1F) == tagReg) {   // cbz wTag
                                    dblGuard = YES; dblGuardAddr = p - (uint64_t)k * 4; dblGuardOld = wq; break;
                                }
                                if ((wq & 0x7F000000) == 0x35000000 && ((wq >> 0) & 0x1F) == tagReg) {   // cbnz wTag
                                    dblGuard = YES; dblGuardAddr = p - (uint64_t)k * 4; dblGuardOld = wq; break;
                                }
                            }
                        }
                    }
                    // 权益锚定门直接给最高分(99) — 与形态真门同级, 优先试
                    if (entAnchor) isRealGate = YES;
                    // v2.58.126 (用户反馈: "判定点两百多个你认真的吗"): 判据收窄 —
                    //   旧实现把所有 cmp#1+b.cond 都入库 → target-app 242 个点(真门仅 5 个,
                    //   去重后 2 个地址), 用户无法使用。
                    //   新规则: 只有**有证据锚定**的点才入库:
                    //     ① isRealGate (Optional tag 解包 + retain 形态) → score 99
                    //     ② entAnchor (权益状态 API 锚定) → score 99
                    //     ③ dblGuard (双守卫, cbz+门 成组) → score 96
                    //   无锚定的普通门只记日志, 不入库(它们是任何 Swift app 都有的 Optional 解包)。
                    // v2.58.128 (dbg_120 定谳): 加**函数级权益串锚定** — 与 tbz 判据同源。
                    //   实证: 某聚合函数(引用本地校验快照/
                    //   current_entitlements/permanent_entitlements_authoritative 等 13 个权益串)
                    //   内的门被 126 的收窄判据误杀 → 真判定层漏扫。
                    // v2.58.129 (dbg_121 定谳): 改为**以门为中心的就近扫描** —
                    //   128 用 fh 起始窗口, 但引擎"向前找序言"在大函数内部找到子函数头
                    //   (聚合函数内的调用点被归到子头),
                    //   窗口 fh..fh+0x8000 覆盖不到门 → 误报"无锚定"。
                    //   现在: 以门 p 为中心, 向前 0x8000 + 向后 0x1000 扫描(覆盖整个大函数体)。
                    BOOL fnEntOK = isRealGate || dblGuard;
                    if (!fnEntOK) {
                        // v2.58.129 定谳(镜像验证驱动): 序言边界不可靠(sub sp 在函数内到处出现,
                        //   把大函数切碎)。硬窗口也不可靠(大小两难)。
                        //   最终方案: **全局预扫描权益串引用点**, 门只要靠近引用点(±0x2000)即算锚定。
                        //   这直接对应语义"该门与权益字段读写在同一代码区域"。
                        static uint64_t *entRefs = NULL; static int nEntRefs = 0;
                        if (!entRefs) {
                            entRefs = (uint64_t *)malloc(sizeof(uint64_t) * 8192);
                            for (uint64_t q = textVM; q + 8 <= textVM + textSize && nEntRefs < 8192; q += 4) {
                                uint32_t a1 = *(const uint32_t *)((uintptr_t)q + (uintptr_t)slide);
                                if ((a1 & 0x9F000000) != 0x90000000) continue;
                                uint32_t a2 = *(const uint32_t *)((uintptr_t)(q + 4) + (uintptr_t)slide);
                                if ((a2 & 0xFF800000) != 0x91000000) continue;
                                if (((a2 >> 0) & 0x1F) != ((a2 >> 5) & 0x1F)) continue;
                                int64_t im2 = (int64_t)((((a1 >> 5) & 0x7FFFF) << 2) | ((a1 >> 29) & 3));
                                if (im2 & (1 << 20)) im2 -= (int64_t)(1 << 21);
                                uintptr_t ip = (uintptr_t)q + (uintptr_t)slide;
                                uint64_t tgt = (ip & ~0xFFFULL) + ((uint64_t)im2 << 12) + ((a2 >> 10) & 0xFFF);
                                // v2.58.130 (dbg_121 定谳): ★ASLR 修复★
                                //   旧判据 `tgt < baseVM || tgt >= baseVM+64MB` 把**运行时地址**
                                //   (含 slide) 与**静态基址** baseVM 比较 → 实机 slide 几百MB,
                                //   tgt 永远越界 → 全部 continue → 函数级锚定从未生效!
                                //   修: 范围检查用静态 VA (q & ~0xFFF | im2/tgt 的静态分量),
                                //   读串仍用运行时地址。
                                uint64_t tgtStatic = (q & ~0xFFFULL) + ((uint64_t)im2 << 12) + ((a2 >> 10) & 0xFFF);
                                //   静态空间判界用 128MB(target-app 镜像总长 ~76MB; 64MB 会切掉
                                //   __swift5_reflstr 尾部, 权益属性名在那)
                                if (tgtStatic < baseVM || tgtStatic >= baseVM + 128ull * 1024 * 1024) continue;
                                const char *str = (const char *)tgt;
                                if (strchr(str, '/') || strstr(str, ".swift")) continue;
                                if (strstr(str, "entitle") || strstr(str, "PaidFeature") ||
                                    strstr(str, "Billing") || strstr(str, "Premium") ||
                                    strstr(str, "Snapshot") || strstr(str, "permanent")) {
                                    entRefs[nEntRefs++] = q;
                                }
                            }
                            mfLog(@"[f8v2] 权益串引用点全局预扫: %d 个", nEntRefs);
                        }
                        for (int r = 0; r < nEntRefs; r++) {
                            uint64_t rv = entRefs[r];
                            if (p >= rv && p - rv <= 0x2000) { fnEntOK = YES; break; }
                            if (rv >= p && rv - p <= 0x800) { fnEntOK = YES; break; }
                        }
                    }
                    if (!fnEntOK) {
                        mfLog(@"[f8v2]   (无锚定门 @%#llx 未入库 — 函数无权益串锚定)",
                              (unsigned long long)(p - textVM));
                        continue;
                    }
                    nVfy++;
                    NSMutableDictionary *pt = [@{
                        @"img": mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main",
                        @"sym": [NSString stringWithFormat:@"sk2vfy@%#llx", (unsigned long long)(p - textVM)],
                        @"vmaddr": @(p),
                        @"slide": @((long)slide),
                        @"score": @(isRealGate ? 99 : 96),
                        @"calls": @(0),
                        @"fn": @(fh),                   // v2.58.126: 函数归属(tbz 门准入用)
                        @"shape": @"sk2vfy",
                        @"kind": @"sk2vfy",
                        @"old": mfLeHex(w1v),
                        @"new": mfLeHex(0xD503201Fu),   // nop → 恒 fall through 到有效路径
                    } mutableCopy];
                    // v2.58.123: 双守卫点一并入库(cbz → NOP), 让"真门+前置判空"作为一组落地
                    if (dblGuard && dblGuardAddr) {
                        pt[@"guard2"] = @{ @"sym": [NSString stringWithFormat:@"sk2vfy@%#llx", (unsigned long long)(dblGuardAddr - textVM)],
                                           @"vmaddr": @(dblGuardAddr), @"old": mfLeHex(dblGuardOld),
                                           @"new": mfLeHex(0xD503201Fu) };
                    }
                    [sk2pts addObject:pt];
                    mfLog(@"[f8v2] ★sk2vfy @%#llx (b.%@ → NOP, cmp@%#llx, fn=%#llx%@%@)",
                          (unsigned long long)(p - textVM), (cond == 1) ? @"ne" : @"eq",
                          (unsigned long long)(cPos - textVM), (unsigned long long)(fh - textVM),
                          isRealGate ? [NSString stringWithFormat:@" ★真门形态 tag=#%#x", tagOff] : @"",
                          entAnchor ? @" ★权益锚定(expiration/revocation/currentEntitlements)" :
                          (dblGuard ? @" ⚠️双守卫(含cbz)" : @""));
                }
                // v2.58.125 (dbg_117 定谳): tbz/tbnz 门扫描 — 旧引擎只找 cmp+b.cond,
                //   漏掉 "bl <检查函数> ; tbz w0,#0,<跳过>" 形态。target-app 实证:
                //     PaidFeatureGate.swift 本地宽限状态机里
                //       0x1027ef500: bl 0x1027f8bac        ← 检查本地权益
                //       0x1027ef504: tbz w0,#0,0x1027ef870 ← ★真门(未扫出!)
                //   这是"布尔返回值直接判"的形态(Bool 结果 bit0), 与 cmp#1 语义等价。
                //   只收: bl 之后紧跟 tbz/tbnz w0,#0 (前向跳转, 同函数内)。
                for (uint64_t p = lo; p + 8 <= hi; p += 4) {
                    uint32_t w1v = *(const uint32_t *)((uintptr_t)p + (uintptr_t)slide);
                    if ((w1v & 0x7F000000) != 0x36000000) continue;   // tbz/tbnz
                    uint32_t bit = ((w1v >> 19) & 0x1F) | ((w1v >> 26) & 0x20);
                    if (bit != 0) continue;                            // 只收 bit0 (Bool)
                    if (((w1v >> 0) & 0x1F) != 0) continue;            // 只收 w0 (返回值寄存器)
                    int32_t i14 = (int32_t)((w1v >> 5) & 0x3FFF);
                    if (i14 & (1 << 13)) i14 -= (1 << 14);
                    uint64_t tTgt = p + ((uint64_t)i14 << 2);
                    if (tTgt <= p) continue;                           // 前向跳转
                    // 前 2 条内必须有 bl(检查函数调用)
                    BOOL hasBl = NO;
                    for (int k = 1; k <= 2; k++) {
                        if (p < textVM + (uint64_t)k * 4) break;
                        uint32_t w2v = *(const uint32_t *)((uintptr_t)(p - k * 4) + (uintptr_t)slide);
                        if ((w2v & 0xFC000000) == 0x94000000) { hasBl = YES; break; }
                    }
                    if (!hasBl) continue;
                    uint64_t blPos = 0;
                    for (int k = 1; k <= 2; k++) {
                        uint32_t w2v = *(const uint32_t *)((uintptr_t)(p - k * 4) + (uintptr_t)slide);
                        if ((w2v & 0xFC000000) == 0x94000000) { blPos = p - k * 4; break; }
                    }
                    // 去重(同地址不重复入库)
                    BOOL dupT = NO;
                    for (NSDictionary *e in sk2pts)
                        if ([e[@"vmaddr"] unsignedLongLongValue] == p) { dupT = YES; break; }
                    if (dupT) continue;
                    // 检查被调用函数是否属于"权益类"(符号归属) — 用 bl 目标反查符号名
                    NSString *blTargetSym = nil;
                    if (blPos) {
                        uint32_t bw = *(const uint32_t *)((uintptr_t)blPos + (uintptr_t)slide);
                        int64_t bim = (int64_t)(bw & 0x3FFFFFF);
                        if (bim & (1 << 25)) bim -= (int64_t)(1 << 26);
                        uint64_t bt = blPos + ((uint64_t)bim << 2);
                        for (int vk = 0; vk < nVfyStub; vk++)
                            if (vfyStubVM[vk] == bt) { blTargetSym = [NSString stringWithUTF8String:vfyStubNames[vk]]; break; }
                    }
                    // v2.58.126 (用户反馈: "判定点两百多个你认真的吗"): 函数级权益串锚定 —
                    //   旧实现把全 binary 所有 "bl + tbz w0,#0" 都入库 → target-app 62 个,
                    //   绝大多数是无关函数(iterator.next / 普通布尔检查)。
                    //   新规则: 只收**函数内引用权益相关字符串**的 tbz 门。
                    //   target-app 实证: PaidFeatureGate 状态机(fn=0x27ea74c)引用
                    //   "[PaidFeatureGate] using local entitlement grace" 等串, 其 tbz 门
                    //   (0x27eb49c 平台认证 / 0x27eb504 本地权益)才是真判定点。
                    BOOL fnEntAnchor = NO;
                    {
                        // v2.58.126 修正3: 扫描窗口固定 0x8000(32KB) — 覆盖大函数(PaidFeatureGate
                        //   状态机实测 20KB+), 又不会跑到邻居函数(镜像验证: 0x20000 会误命中的
                        //   其他函数的串)。函数边界扫描在 strip 后不可靠(非标准序言), 故用固定窗。
                        uint64_t qEnd = fh + 0x8000;
                        if (qEnd > textVM + textSize) qEnd = textVM + textSize;
                        for (uint64_t q = fh; q + 8 <= qEnd; q += 4) {
                            uint32_t a1 = *(const uint32_t *)((uintptr_t)q + (uintptr_t)slide);
                            if ((a1 & 0x9F000000) != 0x90000000) continue;      // adrp
                            uint32_t a2 = *(const uint32_t *)((uintptr_t)(q + 4) + (uintptr_t)slide);
                            if ((a2 & 0xFF800000) != 0x91000000) continue;      // add xN,xN,#imm
                            if (((a2 >> 0) & 0x1F) != ((a2 >> 5) & 0x1F)) continue;
                            int64_t im2 = (int64_t)((((a1 >> 5) & 0x7FFFF) << 2) | ((a1 >> 29) & 3));
                            if (im2 & (1 << 20)) im2 -= (int64_t)(1 << 21);
                            uintptr_t ip = (uintptr_t)q + (uintptr_t)slide;
                            uint64_t tgt = (ip & ~0xFFFULL) + ((uint64_t)im2 << 12) + ((a2 >> 10) & 0xFFF);
                            // v2.58.130 (dbg_121 定谳): ★ASLR 修复★ — 同上。
                            //   tgt 含 slide(运行时), baseVM 是静态 → 必须用静态分量比较。
                            uint64_t tgtStatic = (q & ~0xFFFULL) + ((uint64_t)im2 << 12) + ((a2 >> 10) & 0xFFF);
                            if (tgtStatic < baseVM || tgtStatic >= baseVM + 128ull * 1024 * 1024) continue;
                            const char *str = (const char *)tgt;
                            if (strstr(str, "entitle") || strstr(str, "PaidFeature") ||
                                strstr(str, "Billing") || strstr(str, "Premium")) {
                                fnEntAnchor = YES; break;
                            }
                        }
                    }
                    if (!fnEntAnchor) {
                        mfLog(@"[f8v2]   (tbz 门 @%#llx 未入库 — 函数无权益串锚定)", (unsigned long long)(p - textVM));
                        continue;
                    }
                    nVfy++;
                    NSMutableDictionary *tp = [@{
                        @"img": mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main",
                        @"sym": [NSString stringWithFormat:@"sk2vfy@%#llx", (unsigned long long)(p - textVM)],
                        @"vmaddr": @(p),
                        @"slide": @((long)slide),
                        @"score": @(95),
                        @"calls": @(0),
                        @"shape": @"sk2vfy",
                        @"kind": @"sk2vfy",
                        @"old": mfLeHex(w1v),
                        @"new": mfLeHex(0xD503201Fu),   // nop → 恒 fall through(Bool 恒真路径)
                    } mutableCopy];
                    if (blTargetSym.length) tp[@"note"] = [NSString stringWithFormat:@"bl %@", blTargetSym];
                    [sk2pts addObject:tp];
                    mfLog(@"[f8v2] ★sk2vfy(tbz) @%#llx (tbz w0,#0 → NOP, bl@%#llx%@, fn=%#llx)",
                          (unsigned long long)(p - textVM), (unsigned long long)(blPos - textVM),
                          blTargetSym.length ? [NSString stringWithFormat:@" → %@", [blTargetSym substringFromIndex:MIN(20u, (unsigned)blTargetSym.length)]] : @"",
                          (unsigned long long)(fh - textVM));
                }
            }
            mfLog(@"[f8v2] sk2vfy: 验证stub=%d 调用点=%d 验证函数=%d 判定门=%d 个",
                  nVfyStub, nVfyCall, nVfyFn, nVfy);
        }
    }


    // v2.58.160: pro 校验器 fn 列表 — 函数级作用域, sk2plan 段填充, sk2recipe 段遍历。
    //   (真机 dbg_146: sk2recipe 原遍历 sk2pts 比较门 fn, 漏掉有 active 构造块但无比较门的校验器)
    NSMutableArray *g_sk2ProValidatorFns = [NSMutableArray array];

    // =====================================================================
    // sk2plan: 名称比对门 — 服务器票据/内存状态型 app 的通用判定指纹。
    //   动机: 目标判定非单一 bool 门, 而是枚举状态 ⇄ 名称比对,
    //   分布式消费; 侦查扫描应"识别这一类", 而非硬编码单靶子)。
    //   通用指纹(零 app 硬编码): 一段 movz/movk 立即数链, 拼出的字节是 ASCII 订阅计划名
    //   (含 pro/year/month/life/prem/annual 等词) → 这是 Swift small-string 计划名字面量,
    //   紧邻的字符串相等判定就是"当前权益是否==某 pro 计划"的门。
    //   实证: 某校验函数里
    //     movz/movk 链拼出 "monthly"
    //     cmp 比对拼出 "pro_yearly_2026" 等计划名字面量
    //   v2.58.146: 仅记录 + 归属函数, 不入库(patch 策略待定: 单点 patch 已证分布式不亮,
    //   下一步评估读侧拦截 vs 校验函数返回值改写)。
    // =====================================================================
    {
        int nPlan = 0;
        // 两阶段: ① 扫集所有"强计划名"命中(按归属函数聚合) ② 只报同函数≥2命中(真校验器: 多计划名并排比对)
        //   强词表 = 精确订阅计划名(去掉 pro_/sub_/_pro 等宽子串, 它们误命中函数名/UI串片段)。
        NSMutableDictionary<NSNumber *, NSMutableArray *> *planByFn = [NSMutableDictionary dictionary];
        for (uint64_t p = textVM; p + 4 <= textVM + textSize; p += 4) {
            uint32_t w = *(const uint32_t *)((uintptr_t)p + (uintptr_t)slide);
            if ((w & 0xFF800000) != 0xD2800000) continue;   // MOVZ x
            uint32_t rd = w & 0x1F;
            uint32_t hw0 = (w >> 21) & 3;
            uint64_t val = (uint64_t)((w >> 5) & 0xFFFF) << (hw0 * 16);
            int npc = 0; uint64_t q = p + 4;
            for (; npc < 3 && q + 4 <= textVM + textSize; q += 4) {
                uint32_t mw = *(const uint32_t *)((uintptr_t)q + (uintptr_t)slide);
                if ((mw & 0xFF800000) != 0xF2800000 || (mw & 0x1F) != rd) break;
                uint32_t hw = (mw >> 21) & 3;
                val |= (uint64_t)((mw >> 5) & 0xFFFF) << (hw * 16);
                npc++;
            }
            if (npc == 0) continue;
            uint8_t bs[8]; for (int i = 0; i < 8; i++) bs[i] = (val >> (i * 8)) & 0xFF;
            int printable = 0; char asc[9];
            for (int i = 0; i < 8; i++) { uint8_t c = bs[i]; asc[i] = (c >= 0x20 && c < 0x7F) ? (char)c : 0; if (c >= 0x20 && c < 0x7F) printable++; }
            asc[8] = 0;
            if (printable < 6) continue;                    // 半 ASCII 噪音守卫
            // 强词: 精确计划名(不用 pro_/sub_ 宽子串)
            if (!(strstr(asc, "monthly") || strstr(asc, "yearly") || strstr(asc, "lifetime") ||
                  strstr(asc, "annual") || strstr(asc, "_2026") || strstr(asc, "pro_year") ||
                  strstr(asc, "pro_month"))) continue;
            uint64_t fh = 0;
            for (uint64_t b = p; b > textVM && p - b < 0x4000; b -= 4) {
                uint32_t bw = *(const uint32_t *)((uintptr_t)b + (uintptr_t)slide);
                if (bw == 0xD503237F ||
                    ((bw & 0xFF8003FF) == 0xD10003FF && ((bw >> 10) & 0xFFF)) ||
                    ((bw & 0xFFC003E0) == 0xA98003E0)) { fh = b; break; }
            }
            if (!fh) continue;
            NSMutableArray *arr = planByFn[@(fh)];
            if (!arr) { arr = [NSMutableArray array]; planByFn[@(fh)] = arr; }
            [arr addObject:@{ @"va": @(p - textVM), @"nm": [NSString stringWithUTF8String:asc] }];
            nPlan++;
        }
        // ② 只报真校验器(同函数≥2 计划名并排) + ★入库真 pro 校验器的比较门(可 ⚡)
        int nCluster = 0, nGateReg = 0;
        // 计划名 small-string 立即数近邻判定(通用, 零地址硬编码)
        BOOL (^planLitNear)(uint64_t, uint64_t) = ^BOOL(uint64_t gateVA, uint64_t fnHead) {
            uint64_t lo2 = (gateVA > fnHead + 28 * 4) ? gateVA - 28 * 4 : fnHead;
            for (uint64_t k = lo2; k < gateVA; k += 4) {
                uint32_t w2 = *(const uint32_t *)((uintptr_t)k + (uintptr_t)slide);
                if ((w2 & 0xFF800000) != 0xD2800000) continue;   // MOVZ x
                uint32_t rd2 = w2 & 0x1F, hw0b = (w2 >> 21) & 3;
                uint64_t val2 = (uint64_t)((w2 >> 5) & 0xFFFF) << (hw0b * 16);
                uint64_t q2 = k + 4; int np2 = 0;
                for (; np2 < 3; q2 += 4) {
                    uint32_t mw = *(const uint32_t *)((uintptr_t)q2 + (uintptr_t)slide);
                    if ((mw & 0xFF800000) != 0xF2800000 || (mw & 0x1F) != rd2) break;
                    val2 |= (uint64_t)((mw >> 5) & 0xFFFF) << (((mw >> 21) & 3) * 16); np2++;
                }
                if (np2 == 0) continue;
                char b8[8]; for (int t = 0; t < 8; t++) b8[t] = (val2 >> (t * 8)) & 0xFF;
                if (memmem(b8, 8, "month", 5) || memmem(b8, 8, "year", 4) ||
                    memmem(b8, 8, "lifetim", 7) || memmem(b8, 8, "_2026", 5)) return YES;
            }
            return NO;
        };
        for (NSNumber *fnKey in [planByFn.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
            NSArray *arr = planByFn[fnKey];
            if (arr.count < 2) continue;
            nCluster++;
            uint64_t fh = [fnKey unsignedLongLongValue];
            NSMutableString *names = [NSMutableString string];
            BOOL isProValidator = NO;
            for (NSDictionary *e in arr) {
                if (names.length) [names appendString:@"/"];
                [names appendString:e[@"nm"]];
                NSString *nm = e[@"nm"];
                if ([nm containsString:@"_2026"] || [nm containsString:@"pro_year"]) isProValidator = YES;
            }
            mfLog(@"[f8v2] ★sk2plan 校验器簇 fn=%#llx (%lu 计划名: %@)%@",
                  (unsigned long long)fh, (unsigned long)arr.count, names,
                  isProValidator ? @" ★真 pro 校验器" : @"");
            if (!isProValidator) continue;   // 只入库真 pro 校验器(含 pro_year/_2026), 泛计划名簇不动
            [g_sk2ProValidatorFns addObject:@(fh)];   // v2.58.160: 收集 pro 校验器 fn → sk2recipe 遍历源
                                                       //   (真机 dbg_146 定谳: sk2recipe 遍历 sk2pts 比较门 fn 漏掉
                                                       //    有 active 构造块但无比较门的校验器, 如新版 0x102a5049c)
            // 该函数内定位计划名比较门: bl + 紧跟 tbz w0,#0 前向, 且门前 28 条有 small-string 计划名
            uint64_t qEnd = fh + 0x8000; if (qEnd > textVM + textSize) qEnd = textVM + textSize;
            for (uint64_t g = fh; g + 4 <= qEnd; g += 4) {
                uint32_t w = *(const uint32_t *)((uintptr_t)g + (uintptr_t)slide);
                if ((w & 0x7F000000) != 0x36000000) continue;        // tbz(非tbnz)
                if ((w & 0x1F) != 0) continue;                       // Rt=w0
                if ((((w >> 19) & 0x1F) | ((w >> 26) & 0x20)) != 0) continue;  // bit0
                int32_t i14 = (int32_t)((w >> 5) & 0x3FFF);
                if (i14 & (1 << 13)) i14 -= (1 << 14);
                if (i14 <= 0) continue;                              // 前向(不匹配→跳过授权)
                // 前 2 条内有 bl(String== 调用)
                BOOL hasBl = NO;
                for (int kk = 1; kk <= 2; kk++) {
                    uint32_t bw = *(const uint32_t *)((uintptr_t)(g - kk * 4) + (uintptr_t)slide);
                    if ((bw & 0xFC000000) == 0x94000000) { hasBl = YES; break; }
                }
                if (!hasBl) continue;
                if (!planLitNear(g, fh)) continue;                  // 门前有计划名 small-string
                BOOL dup = NO;
                for (NSDictionary *e in sk2pts) if ([e[@"vmaddr"] unsignedLongLongValue] == g) { dup = YES; break; }
                if (dup) continue;
                [sk2pts addObject:[@{
                    @"img": mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main",
                    @"sym": [NSString stringWithFormat:@"sk2vfy@%#llx", (unsigned long long)(g - textVM)],
                    @"vmaddr": @(g), @"slide": @((long)slide),
                    @"score": @(98), @"calls": @(0), @"fn": @(fh),
                    @"shape": @"sk2vfy", @"kind": @"sk2plan",
                    @"old": mfLeHex(w), @"new": mfLeHex(0xD503201Fu),   // tbz → NOP(计划名比较恒匹配→授权)
                } mutableCopy]];
                nGateReg++;
                mfLog(@"[f8v2]   ↳ 计划名比较门 @%#llx (tbz w0 → NOP, 恒匹配走授权)", (unsigned long long)(g - textVM));
            }
        }
        mfLog(@"[f8v2] sk2plan: 强命中=%d, 校验器簇=%d 个, ★入库 pro 比较门=%d 个(sk2vfy 形态, 可 ⚡) — 通用指纹",
              nPlan, nCluster, nGateReg);
    }

    // =====================================================================
    // sk2recipe (v2.58.155): active 状态构造配方自动提取 — 服务器票据/内存状态型 app 的
    //   "本地构造授权结构"通用能力。sk2plan 锚定 pro 校验器后, 在其"计划名匹配成功分支"里,
    //   宿主自己有一段构造 active 状态结构的代码(strb #1 写 disc + 一串 stp 写 small-string
    //   周期/来源/状态词 + adrp 名称指针 + strd 有效期)。数据流追踪每条 store 的源寄存器值,
    //   反推出 {字段偏移 → 类型/值} 配方 → 六项自检 → 过则自动录入 mfInjectRecipes 持久层。
    //   规则(零人工): ① 计划档位优先级(lifetime>yearly>monthly…)自动选计划名常量
    //                 ② 有效期 = now+100年(运行时算, MF_FLD_NOWPLUS)
    //   注入由 MFProbe hook_inject 执行器落地(hook 选择器入口按配方填结构)。
    // =====================================================================
    {
        extern void mfAppPatchEntDumpsMerge(NSArray *);   // hookinj 判定点入库(并入 patch 引擎)
        const char *PERIODW[] = {"lifetime","perpetual","forever","yearly","annual","monthly","weekly"};
        const int  PERIODP[]  = {0,1,2,3,4,5,6};   // 档位优先级(小=更持久)
        // 状态语义槽词表: 订阅生命周期词(正向+负向都算"状态槽")。宿主可能条件构造 active/expired,
        //   我要构造授权态 → 不管它那条分支写哪个, 只要这个槽装的是生命周期词, 组装时强制填 "active"。
        const char *STATUSW[] = {"active","valid","subscribed","purchased","entitled",
                                 "expired","inactive","cancelled","canceled","revoked","none","trial","grace","lapsed"};
        const int STATUSW_N = 14;

        // —— 局部数据流状态: 每寄存器一个 (kind,val) ——
        //   kind: 0=unknown 1=imm 2=addr 3=ivaroff(=某ivar全局VA) 4=structbase(=ivar全局VA)
        typedef struct { int kind; uint64_t val; } RegV;

        // ① 计划名档位选择(只读段常量, 档位优先 + 地址次序)
        __block uint64_t planVA = 0; __block int planCount = 0; __block int planPrio = 99;
        // 用 LC 已解析的精确 __cstring 段范围(有界, 防越界/误命中代码区)
        if (cstrVM && cstrSize) {
            uintptr_t cbase = (uintptr_t)cstrVM + (uintptr_t)slide;
            uint64_t i2 = 0;
            while (i2 < cstrSize) {
                const char *s = (const char *)(cbase + i2);
                if (*s < 0x20 || *s >= 0x7F) { i2++; continue; }
                uint64_t j = i2; int len = 0;
                while (j < cstrSize && *(const char*)(cbase+j) >= 0x20 && *(const char*)(cbase+j) < 0x7F && len < 48) { j++; len++; }
                if (j < cstrSize && *(const char*)(cbase+j) == 0 && len >= 6 && len <= 40) {
                    char buf[48]; memcpy(buf, s, len); buf[len] = 0;
                    for (int t = 0; t < 7; t++) {
                        if (strstr(buf, PERIODW[t])) {
                            BOOL idlike = (strncmp(buf,"pro_",4)==0) || (strcmp(buf,PERIODW[t])==0);
                            if (idlike && PERIODP[t] < planPrio) {
                                int pc = (strncmp(buf,"pro_",4)==0) ? (int)(4+strlen(PERIODW[t])) : (int)strlen(PERIODW[t]);
                                planPrio = PERIODP[t];
                                planCount = pc;
                                planVA = cstrVM + i2;     // 该常量 VA
                            }
                            break;
                        }
                    }
                }
                i2 = j + 1;
            }
        }

        // ② 遍历 sk2plan 已入库的 pro 校验器函数(sk2pts 里 kind=sk2plan 的 fn), 提取 active 构造块
        NSMutableSet *doneFns = [NSMutableSet set];
        int nRecipe = 0;
        // v2.58.160: 遍历源 = sk2plan 识别的全部 pro 校验器 fn(独立于比较门), 而非 sk2pts。
        //   真机 dbg_146 定谳: 有 active 构造块的校验器(如新版 0x102a5049c)不一定有计划名比较门,
        //   遍历 sk2pts(比较门 fn)会漏掉它 → 0 配方。改遍历 g_sk2ProValidatorFns 全集。
        for (NSNumber *fnNum in g_sk2ProValidatorFns) {
            uint64_t fh = [fnNum unsignedLongLongValue];
            if (!fh || [doneFns containsObject:@(fh)]) continue;
            [doneFns addObject:@(fh)];

            RegV reg[32]; memset(reg, 0, sizeof(reg));
            // v2.58.159: 多块收集 — 校验器可能构造多个状态块(前导小块/active/free), 顺序因 codegen 而异。
            //   不再假设"第一块=active"(dbg_142 旧规则在新版切错块)。收集所有 disc 块, 最后择优:
            //   字段最多 且 含 period+status 串 = 真 active 块。这是"照抄布局"不依赖块顺序的关键。
            #define MFRB_MAXBLK 8
            struct { uint64_t sbIvar; uint64_t fOff[32]; int fTy[32]; uint64_t fVal[32]; int nF;
                     uint32_t structMax; int nPeriod, nStatus, nInput;
                     uint64_t forceVA; uint32_t forceOld, forceNew; } blk[MFRB_MAXBLK];   // v2.58.161 方案B: disc 授权 bool 强制点
            memset(blk, 0, sizeof(blk));
            int nBlk = -1;   // 当前块索引(-1=还没遇到 disc)
            // v2.58.161 方案B: 追踪最近的 "and wRd,wS,#1"(取授权 bool 低位) — disc 值来源。
            //   patch 成 movz wRd,#1 → 宿主用它自己的运行时偏移构造 active(绕过"我算运行时偏移")。
            struct { uint64_t va; uint32_t word; } recentAnd[32];
            memset(recentAnd, 0, sizeof(recentAnd));

            uint64_t qEnd = fh + 0x800; if (qEnd > textVM + textSize) qEnd = textVM + textSize;
            for (uint64_t a = fh; a + 4 <= qEnd; a += 4) {
                uint32_t w = *(const uint32_t *)((uintptr_t)a + (uintptr_t)slide);
                // MOVZ
                if ((w & 0xFF800000) == 0xD2800000) { int rd=w&0x1F; reg[rd].kind=1; reg[rd].val=(uint64_t)((w>>5)&0xFFFF)<<(((w>>21)&3)*16); continue; }
                // MOVK
                if ((w & 0xFF800000) == 0xF2800000) { int rd=w&0x1F; if(reg[rd].kind!=1)reg[rd].val=0; reg[rd].kind=1; uint32_t hw=(w>>21)&3; reg[rd].val=(reg[rd].val & ~(0xFFFFULL<<(hw*16)))|((uint64_t)((w>>5)&0xFFFF)<<(hw*16)); continue; }
                // MOVN (64)
                if ((w & 0xFF800000) == 0x92800000) { int rd=w&0x1F; reg[rd].kind=1; reg[rd].val=~((uint64_t)((w>>5)&0xFFFF)<<(((w>>21)&3)*16)); continue; }
                // ADRP
                if ((w & 0x9F000000) == 0x90000000) { int rd=w&0x1F; int64_t immlo=(w>>29)&3,immhi=(w>>5)&0x7FFFF; int64_t imm=(immhi<<2)|immlo; if(imm&(1<<20))imm-=(1<<21); reg[rd].kind=2; reg[rd].val=(a&~0xFFFULL)+(imm<<12); continue; }
                // ADD imm (64)
                if ((w & 0xFFC00000) == 0x91000000) { int rd=w&0x1F,rn=(w>>5)&0x1F; uint64_t imm=((w>>10)&0xFFF)<<(((w>>22)&1)?12:0); if(reg[rn].kind==2){reg[rd].kind=2;reg[rd].val=reg[rn].val+imm;}else reg[rd].kind=0; continue; }
                // ADD xd, xn, xm(reg): 任一操作数是 kind3(loaded 偏移) → structbase(照抄, 覆盖两种 codegen)
                //   旧式: add self, <ldr 常量ivar偏移>(kind3.val=全局VA静态可知)
                //   新式: add self, <ldrsw 元数据偏移>(kind3.val=0, Swift resilient, 偏移运行时才知)
                if ((w & 0xFF200000) == 0x8B000000) {
                    int rd=w&0x1F, rn=(w>>5)&0x1F, rm=(w>>16)&0x1F;
                    if (reg[rm].kind==3) { reg[rd].kind=4; reg[rd].val=reg[rm].val; }
                    else if (reg[rn].kind==3) { reg[rd].kind=4; reg[rd].val=reg[rn].val; }
                    else reg[rd].kind=0;
                    continue;
                }
                // LDR/LDRSW/LDUR → kind3(loaded 偏移)。静态(base=adrp 常量 ivar-off 页)→ val=全局VA;
                //   运行时(base 来自 bl 返回的类型元数据描述符, 新版)→ val=0。两种都标 kind3, 使后续 add
                //   识别为 structbase — "照抄布局"不依赖偏移是否静态可知(这是新版 codegen-agnostic 的关键)。
                if ((w & 0xFFC00000) == 0xF9400000) {   // LDR xt,[xn,#imm]
                    int rt=w&0x1F,rn=(w>>5)&0x1F; uint64_t imm=((w>>10)&0xFFF)*8;
                    reg[rt].kind=3; reg[rt].val=(reg[rn].kind==2)?(reg[rn].val+imm):0; continue;
                }
                if ((w & 0xFFC00000) == 0xB9800000) { reg[w&0x1F].kind=3; reg[w&0x1F].val=0; continue; }   // LDRSW xt,[xn,#imm]
                if ((w & 0xFFE00C00) == 0xF8400000) { reg[w&0x1F].kind=3; reg[w&0x1F].val=0; continue; }   // LDUR xt,[xn,#simm]
                // v2.58.161 方案B: AND wRd,wRn,#1(取 bool 低位) → 记为该寄存器最近的授权-bool 定义点。
                //   编码: 32-bit AND(imm) N=0 immr=0 imms=0 → 0x12000000 | (Rn<<5) | Rd
                if ((w & 0xFFFFFC00) == 0x12000000) { int rd=w&0x1F; recentAnd[rd].va=a; recentAnd[rd].word=w; }
                // STRB imm: strb wt,[xn,#imm]
                if ((w & 0xFFC00000) == 0x39000000) {
                    int rt=w&0x1F,rn=(w>>5)&0x1F; uint32_t imm=(w>>10)&0xFFF;
                    if (reg[rn].kind==4) {
                        if (imm==0) {   // 新块起点(off0 写 disc) — 多块收集, 不再 break
                            if (nBlk+1 < MFRB_MAXBLK) nBlk++;
                            blk[nBlk].sbIvar = reg[rn].val;
                            // 方案B: disc 值来自近处 "and wRt,#1"(该 rt 最近一次, 函数窗口内) → 记强制点。
                            //   窗口放宽到 0x800(dbg_148: active 块 disc 距 and 源 240B, 因两处 disc 经 mov 中转
                            //   共用同一 and 源, 窄窗口漏掉 best 块)。old 字节校验兜底防误 patch(recentAnd 只被
                            //   and wRt,#1 更新, mov 不动它 → disc 的 rt 查到的即真源 and; 记错则运行时 old 不符拒打)。
                            if (recentAnd[rt].va && (a - recentAnd[rt].va) <= 0x800) {
                                blk[nBlk].forceVA  = recentAnd[rt].va;
                                blk[nBlk].forceOld = recentAnd[rt].word;
                                blk[nBlk].forceNew = 0x52800000u | (1u<<5) | rt;   // movz wRt,#1
                            }
                        }
                        if (nBlk < 0) continue;   // off!=0 但还没起块 — 忽略
                        uint64_t v = (reg[rt].kind==1)?(reg[rt].val&0xFF):1;
                        if (blk[nBlk].nF < 32) { blk[nBlk].fOff[blk[nBlk].nF]=imm; blk[nBlk].fTy[blk[nBlk].nF]=0/*u8*/; blk[nBlk].fVal[blk[nBlk].nF]=v; blk[nBlk].nF++; }
                        if (imm+1>blk[nBlk].structMax) blk[nBlk].structMax=imm+1;
                    }
                    continue;
                }
                // STR/STP/STRD [xn,#imm] where xn=structbase
                if ((w & 0xFFC00000) == 0xF9000000 || (w & 0xFFC00000) == 0xA9000000 || (w & 0xFFC00000) == 0xFD000000) {
                    int rn=(w>>5)&0x1F;
                    if (reg[rn].kind!=4 || nBlk<0) continue;
                    BOOL isStp = ((w & 0xFFC00000)==0xA9000000);
                    BOOL isStrd = ((w & 0xFFC00000)==0xFD000000);
                    int rt=w&0x1F, rt2=(w>>10)&0x1F;
                    int32_t imm; uint64_t o0,o1=0; int cnt=1;
                    if (isStp) { imm=(w>>15)&0x7F; if(imm&0x40)imm-=0x80; o0=imm*8; o1=o0+8; cnt=2; }
                    else { o0=((w>>10)&0xFFF)*8; }
                    int rts[2]={rt,rt2}; uint64_t offs[2]={o0,o1};
                    for (int e=0;e<cnt;e++) {
                        if (blk[nBlk].nF >= 32) break;
                        uint64_t oo=offs[e]; int rr=rts[e];
                        if (oo+8>blk[nBlk].structMax) blk[nBlk].structMax=(uint32_t)(oo+8);
                        int fi = blk[nBlk].nF;
                        if (isStrd) {
                            blk[nBlk].fOff[fi]=oo; blk[nBlk].fTy[fi]=5/*now_plus*/; blk[nBlk].fVal[fi]=100; blk[nBlk].nF++;
                            continue;
                        }
                        RegV sv = reg[rr];
                        if (sv.kind==1) {
                            char a8[8]; for(int t=0;t<8;t++)a8[t]=(sv.val>>(t*8))&0xFF;
                            int pr=0; for(int t=0;t<8;t++){uint8_t c=a8[t]; if(c>=0x20&&c<0x7F)pr++; else if(c)pr=-99;}
                            if (pr>=3) {
                                char lower[9]; int L=0; for(int t=0;t<8&&a8[t];t++){lower[t]=a8[t]|0x20;L++;} lower[L]=0;
                                for(int t=0;t<7;t++) if(strstr(lower,PERIODW[t])){blk[nBlk].nPeriod++;break;}
                                for(int t=0;t<STATUSW_N;t++) if(strstr(lower,STATUSW[t])){blk[nBlk].nStatus++;break;}
                                blk[nBlk].fOff[fi]=oo; blk[nBlk].fTy[fi]=1/*bytes*/; blk[nBlk].fVal[fi]=sv.val; blk[nBlk].nF++;
                            } else {
                                blk[nBlk].fOff[fi]=oo; blk[nBlk].fTy[fi]=2/*u64*/; blk[nBlk].fVal[fi]=sv.val; blk[nBlk].nF++;
                            }
                        } else if (sv.kind==2) {
                            blk[nBlk].fOff[fi]=oo; blk[nBlk].fTy[fi]=3/*addr*/; blk[nBlk].fVal[fi]=sv.val; blk[nBlk].nF++;
                        } else {
                            blk[nBlk].fOff[fi]=oo; blk[nBlk].fTy[fi]=4/*input*/; blk[nBlk].fVal[fi]=0; blk[nBlk].nF++;
                            blk[nBlk].nInput++;
                        }
                    }
                }
            }

            // 择优: 所有块里选 含period且含status 的、字段最多者 = 真 active 块。不依赖块顺序。
            int best=-1;
            for (int bi=0; bi<=nBlk; bi++) {
                if (blk[bi].nPeriod<1 || blk[bi].nStatus<1) continue;
                if (best<0 || blk[bi].nF>blk[best].nF) best=bi;
            }
            if (best<0) {
                mfLog(@"[f8v2] sk2recipe fn=%#llx: 无合格 active 块(块数=%d), 跳过", (unsigned long long)(fh-textVM), nBlk+1);
                continue;
            }
            // 摊平选中块到 fieldsXXX(后续组装/自检复用原变量名)
            uint64_t sbIvar = blk[best].sbIvar;
            uint64_t fieldsOff[32]; int fieldsTy[32]; uint64_t fieldsVal[32]; int nF = blk[best].nF;
            memcpy(fieldsOff, blk[best].fOff, sizeof(fieldsOff));
            memcpy(fieldsTy,  blk[best].fTy,  sizeof(fieldsTy));
            memcpy(fieldsVal, blk[best].fVal, sizeof(fieldsVal));
            BOOL haveDisc = YES;   // best 块必含 off0 disc(块起点条件)
            uint32_t structMax = blk[best].structMax;
            int nInput = blk[best].nInput;
            BOOL haveValidity = NO;
            for (int i=0;i<nF;i++) if (fieldsTy[i]==5) { haveValidity=YES; break; }
            int nPeriod = blk[best].nPeriod, nStatus = blk[best].nStatus;
            uint64_t forceVA = blk[best].forceVA; uint32_t forceOld = blk[best].forceOld, forceNew = blk[best].forceNew;   // 方案B 强制点(择优块的)
            if (!planVA) { mfLog(@"[f8v2] sk2recipe fn=%#llx: 无 plan 常量, 跳过", (unsigned long long)(fh-textVM)); continue; }

            // 组装 recipe JSON fields(语义化): period→按档位覆盖成选中计划的 tier 词
            NSMutableArray *jf = [NSMutableArray array];
            [jf addObject:@{@"off":@(0), @"type":@"u8", @"v":@(1)}];   // disc
            const char *tierName = PERIODW[planPrio<7?planPrio:5];
            // input 对: 升序取前两个 = countAndFlags + ptr
            NSMutableArray *inputOffs = [NSMutableArray array];
            for (int i=0;i<nF;i++) if (fieldsTy[i]==4) [inputOffs addObject:@(fieldsOff[i])];
            [inputOffs sortUsingSelector:@selector(compare:)];
            for (int i=0;i<nF;i++) {
                uint64_t oo=fieldsOff[i];
                if (oo==0) continue;   // disc 已加
                int ty=fieldsTy[i]; uint64_t v=fieldsVal[i];
                if (ty==1) {
                    // small-string 语义槽: period 槽→填选中档位(tier); status 槽→强制填 "active"(不管宿主写的 active/expired);
                    //   都不是→常量, 原样照抄。三类分流, 覆盖"条件构造状态"(宿主可能写 expired 分支)。
                    char a8[9]; int L=0; for(int t=0;t<8;t++){uint8_t c=(v>>(t*8))&0xFF; if(c){a8[L++]=c;}} a8[L]=0;
                    char lower[9]; for(int t=0;t<L;t++)lower[t]=a8[t]|0x20; lower[L]=0;
                    BOOL isP=NO,isS=NO;
                    for(int t=0;t<7;t++) if(strstr(lower,PERIODW[t])){isP=YES;break;}
                    if(!isP) for(int t=0;t<STATUSW_N;t++) if(strstr(lower,STATUSW[t])){isS=YES;break;}
                    NSString *sval = isP ? [NSString stringWithUTF8String:tierName]
                                   : (isS ? @"active" : [NSString stringWithUTF8String:a8]);
                    [jf addObject:@{@"off":@(oo), @"type":@"bytes", @"s":sval}];
                    // Swift small-string tag 在 16 字节槽的第 15 字节(0xE0|count), 不是 +7!
                    //   (dbg_142 崩因: tag 误写 +7 → 覆盖 payload + 真 tag 位留 0 → String 被当大字符串解引用垃圾指针崩)
                    [jf addObject:@{@"off":@(oo+15), @"type":@"u8", @"v":@(0xE0 | (int)sval.length)}];
                } else if (ty==2) {
                    // u64: 跳过 small-string tag 型(0xE7 等已被 bytes tag 覆盖); 其余原样
                    uint8_t hi=(v>>56)&0xFF;
                    if (hi>=0xE0 && (v & 0x00FFFFFFFFFFFFFFULL)==0) continue;   // 纯 tag 立即数, 由 bytes 分支处理
                    [jf addObject:@{@"off":@(oo), @"type":@"u64", @"v":[NSString stringWithFormat:@"0x%llx",v]}];
                } else if (ty==3) {
                    [jf addObject:@{@"off":@(oo), @"type":@"immstr", @"v":[NSString stringWithFormat:@"0x%llx",(unsigned long long)(planVA-0x100000000ULL)]}];
                } else if (ty==5) {
                    [jf addObject:@{@"off":@(oo), @"type":@"now_plus", @"years":@(100)}];
                }
            }
            // input 对: [0]=countAndFlags(count) [1]=name ptr
            if (inputOffs.count>=2) {
                uint64_t o0=[inputOffs[0] unsignedLongLongValue], o1=[inputOffs[1] unsignedLongLongValue];
                [jf addObject:@{@"off":@(o0), @"type":@"u64", @"v":[NSString stringWithFormat:@"0x%llx",(0xD000000000000000ULL|(uint64_t)planCount)]}];
                [jf addObject:@{@"off":@(o1), @"type":@"immstr", @"v":[NSString stringWithFormat:@"0x%llx",(unsigned long long)(planVA-0x100000000ULL)]}];
            }

            // selector 定位: 该校验器调用的 ProState 选择器(0x1027ccc70 型)——沿用 sk2plan fn 关联
            //   简化: 选择器 = 读同 ivar 的最早 ldr+ldrb+cmp#1 函数。此处用已知 ivar 反查。
            uint64_t selOff = 0; const uint8_t *selPro = NULL; uint8_t proBuf[16];
            if (sbIvar) {
                uint64_t offA = sbIvar & 0xFFF;
                for (uint64_t s2 = textVM; s2 + 4 <= textVM + textSize; s2 += 4) {
                    uint32_t w = *(const uint32_t *)((uintptr_t)s2 + (uintptr_t)slide);
                    if ((w & 0xFFC00000)!=0xF9400000) continue;
                    if (((w>>10)&0xFFF)*8 != offA) continue;
                    BOOL ld=NO,c1=NO;
                    for (int k=1;k<=7;k++){ uint32_t ww=*(const uint32_t*)((uintptr_t)(s2+k*4)+(uintptr_t)slide); if((ww&0xFFC00000)==0x39400000)ld=YES; if((ww&0x7F80001F)==0x7100001F&&((ww>>10)&0xFFF)==1)c1=YES; }
                    if(!(ld&&c1)) continue;
                    // 往前找函数头
                    for (uint64_t b=s2;b>textVM && s2-b<0x800;b-=4){ uint32_t bw=*(const uint32_t*)((uintptr_t)b+(uintptr_t)slide); if(bw==0xD503237F||((bw&0xFF8003FF)==0xD10003FF&&((bw>>10)&0xFFF))||((bw&0xFFC003E0)==0xA98003E0)){selOff=b-0x100000000ULL;break;} }   // sel_off = VA - image base(MFProbe: target=base+sel_off), 不减 __text 的 0x4000
                    if (selOff) break;
                }
                if (selOff) { memcpy(proBuf, (const void*)((uintptr_t)(selOff+0x100000000ULL)+(uintptr_t)slide), 16); selPro=proBuf; }   // 运行时地址 = VA + slide = (selOff+base) + slide
            }

            // 六项自检
            BOOL ck_disc = haveDisc;
            BOOL ck_name = (inputOffs.count>=2) || (planVA!=0);
            BOOL ck_valid = haveValidity;
            BOOL ck_sel = (selOff!=0);
            BOOL ck_struct = (structMax>=16 && structMax<=512);
            BOOL ck_pro = NO;
            if (selPro) { ck_pro=YES; for(int e=0;e<4;e++){ uint32_t iw=*(const uint32_t*)(selPro+e*4); BOOL safe=((iw&0xFF8003FF)==0xD10003FF)||((iw&0xFFC003E0)==0xA90003E0)||((iw&0xFFC003E0)==0xA98003E0)||((iw&0xFFC003E0)==0x6D0003E0)||((iw&0xFFC003E0)==0x6D8003E0)||((iw&0xFFC003E0)==0xF90003E0)||((iw&0x7F800000)==0x52800000)||((iw&0xFF800000)==0xD2800000)||iw==0xD503201F; if(!safe){ck_pro=NO;break;} } }
            int passed = ck_disc+ck_name+ck_valid+ck_sel+ck_struct+ck_pro;

            // ═══ 方案B(v2.58.161): disc 授权 bool 强制 patch ═══
            //   适用 resilient codegen(新版): ivar 偏移运行时才知 → hookinj 的静态注入落点失效(sel=0/ivar=0)。
            //   方案B 不注入结构, 只把 disc 值来源的 "and wRt,#1" patch 成 "movz wRt,#1" →
            //   宿主用它自己的运行时偏移构造 active(disc 恒=1), 绕过"我算运行时偏移"这个死结。
            //   门槛比 hookinj 低且独立: 只需 disc 块 + period/status(证明是权益构造) + 强制点定位到。
            //   old 字节自带(运行时 patch 前校验), 防漂移/误 patch。是 vm_protect 字节 patch, 走判定点标准路径。
            BOOL bReady = (forceVA != 0) && ck_disc && (nPeriod>=1) && (nStatus>=1);
            if (passed != 6 && bReady) {
                NSString *sym = [NSString stringWithFormat:@"discforce@%#llx", (unsigned long long)(forceVA - 0x100000000ULL)];
                NSDictionary *pt = @{
                    @"img": mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main",
                    @"sym": sym, @"shape": @"discforce", @"kind": @"sk2recipe",
                    @"vmaddr": @(forceVA), @"slide": @((long)slide),
                    @"old": mfLeHex(forceOld), @"new": mfLeHex(forceNew),
                    @"score": @(96), @"calls": @(0), @"fn": @(fh),
                    @"note": [NSString stringWithFormat:@"状态注入·方案B(disc授权bool强制): 校验器 %#llx 内 and→movz#1, 令宿主构造 active(适配运行时偏移)", (unsigned long long)(fh-textVM)],
                };
                extern void mfAppPatchEntDumpsMerge(NSArray *);
                mfAppPatchEntDumpsMerge(@[pt]);
                nRecipe++;
                mfLog(@"[f8v2] ★sk2recipe fn=%#llx: 自检 %d/6 不足但 ★方案B就绪(disc强制点 %#llx: %08x→%08x) → 注册 %@",
                      (unsigned long long)(fh-textVM), passed, (unsigned long long)(forceVA-0x100000000ULL), forceOld, forceNew, sym);
                continue;
            }

            NSString *prologueHex = @"";
            if (selPro) { NSMutableString *ph=[NSMutableString string]; for(int e=0;e<16;e++)[ph appendFormat:@"%02x",selPro[e]]; prologueHex=ph; }
            uint32_t ssz = ((structMax+15)/16)*16;

            NSMutableDictionary *recipe = [@{
                @"selOff": @(selOff),
                @"prologue": prologueHex,
                // ivar 全局 file_off = VA - 0x100000000(项目统一口径, 见 MFProbe 偏移表)
                @"ivarGlobals": sbIvar ? @[@(sbIvar - 0x100000000ULL)] : @[],
                @"structSize": @(ssz),
                @"fields": jf,
            } mutableCopy];

            mfLog(@"[f8v2] ★sk2recipe fn=%#llx: 自检 %d/6 (disc=%d name=%d valid=%d sel=%d struct=%d pro=%d) selOff=%#llx ivar=%#llx size=%u plan='%s'(prio=%d,cnt=%d)",
                  (unsigned long long)(fh-textVM), passed, ck_disc,ck_name,ck_valid,ck_sel,ck_struct,ck_pro,
                  (unsigned long long)selOff, (unsigned long long)(sbIvar?sbIvar-0x100000000ULL:0), ssz, tierName, planPrio, planCount);

            if (passed==6) {
                // v2.58.157: 注册为 hookinj@ 判定点(并入 patch 引擎, 不再独立 prefs)。
                //   sym=hookinj@<fn off>; recipe 配方 JSON 内嵌; shape=hookinj; 用户在判定点列表 ⚡ 执行。
                NSString *sym = [NSString stringWithFormat:@"hookinj@%#llx", (unsigned long long)(fh-textVM)];
                NSDictionary *pt = @{
                    @"img": mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main",
                    @"sym": sym, @"shape": @"hookinj", @"kind": @"sk2recipe",
                    @"vmaddr": @(selOff + 0x100000000ULL), @"slide": @((long)slide),
                    @"score": @(97), @"calls": @(0), @"fn": @(fh),
                    @"note": [NSString stringWithFormat:@"状态注入(hook 选择器+构造 active): plan=%s size=%u", tierName, ssz],
                    @"recipe": recipe,        // 配方 JSON 内嵌点位 — patch 引擎执行时传给 mfProbeInstallRecipe
                };
                extern void mfAppPatchEntDumpsMerge(NSArray *);
                mfAppPatchEntDumpsMerge(@[pt]);
                nRecipe++;
                mfLog(@"[f8v2]   ✅ 注册 hookinj 判定点 %@(默认 off, 判定点列表 ⚡ 执行)", sym);
            } else {
                mfLog(@"[f8v2]   ⚠️ 自检未满(%d/6), 仅记录不入库(防盲注入崩溃)", passed);
            }
        }
        mfLog(@"[f8v2] sk2recipe: 自动录入配方=%d 个", nRecipe);
    }


    NSString *imgName = mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main";
    NSMutableArray *out = [NSMutableArray array];
    NSUInteger f8v2Seg = 0;   // v2.58.76: F8v2 段边界(语义锚定候选, 截断时必须保位)
    // v2.58.16: top6→top12 + CE 消费者无条件保位 — dbg_16 实锤真判定函数
    // (CE 唯一消费者 0x100070cb0, score=5) 被垃圾候选(假 stub 的 calls大户)挤出 top6
    for (NSUInteger i = 0; i < cands.count && i < 12; i++) {
        uint64_t head = [cands[i][@"vmaddr"] unsignedLongValue];
        mfLog(@"[f8v2] cand @%#llx score=%d calls=%d", (unsigned long long)head, [cands[i][@"score"] intValue], [cands[i][@"calls"] intValue]);
        [out addObject:@{
            @"img": imgName,
            @"sym": [NSString stringWithFormat:@"@%#llx", (unsigned long long)head],
            @"vmaddr": @(head),
            @"slide": @((long)slide),
            @"score": cands[i][@"score"] ?: @0,
            @"calls": cands[i][@"calls"] ?: @0,
        }];
    }
    f8v2Seg = out.count;   // v2.58.76: F8v2 段(≤12)到此为止

    // =====================================================================
    // F8v3 (2026-09-12): 判定层深挖 — dbg_17 全候选⚡不亮定谳:
    //   SK 消费层与真判定层之间隔 @Published box/async 闭包, bl 图断链(yimuliaoran
    //   实锤: getter 0x1000a9c18 无 bl 调用者, keypath 间接)。通用算法三步:
    //   ① 语义串引用: __TEXT 内 adrp+add 落到 __cstring/__objc_methname 里含
    //      vip/entitle/premium/purchas/member/subscri/unlock 的串 → 引用函数集
    //   ② SKU 交叉: app 已验证的产品 ID(侦查卡已有, 磁盘扫 com.<bundle 前缀>
    //      备用) 的串引用函数 → 引用函数集(判定必比较 SKU)
    //   ③ fan-in 共享 accessor: 被语义串函数集×SKU 函数集**共同 bl 的本地函数**
    //      = 全 app 共用的判定 accessor(yimuliaoran 0x1000a65f0, 17 个调用者实锤)
    //      — 恒真它 = 拦截读侧, 不依赖写侧数据流。零 per-app 硬编码, SKU 串动态发现。
    // =====================================================================
    @autoreleasepool {
    // ---- ① 语义串表: 扫 __TEXT 的 cstring 区(LC 内全部只读 const 段) ----
    // 引用扫一次 __text: adrp+add(±0/4/8/12 窗口) → 目标落段内 → 记 (pc, 目标串)
    // 需要段表(const 段列表) — 从 segs[](已存)派生: fileoff=0 不可写, size>0, 含 __cstring 类
    // 简化: 全 segs[] 段里 vmaddr 落在 [imgBase, imgBase+__TEXT vmsize) 外的 const 区都算
    // 实操: 只扫 __TEXT.__cstring + __objc_methname(引用函数的目标判断用字符串内容)
    static const char *kSemWords[] = { "vip", "entitle", "premium", "purchas", "member", "subscri", "unlock" };
    // cstring 区 vmaddr/size(扫描时 LC 循环顺带收集) — 重走 LC 拿 __cstring/__objc_methname
    uint64_t cstrVM = 0, cstrSize = 0, methVM = 0, methSize = 0;
    lc = (const struct load_command *)((const uint8_t *)mh + sizeof(struct mach_header_64));
    for (uint32_t c = 0; c < mh->ncmds; c++, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
        if (lc->cmd != LC_SEGMENT_64) continue;
        const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
        const struct section_64 *sc = (const struct section_64 *)((const uint8_t *)sg + sizeof(struct segment_command_64));
        for (uint32_t s = 0; s < sg->nsects; s++, sc++) {
            if (!strcmp(sc->segname, "__TEXT") && !strcmp(sc->sectname, "__cstring")) { cstrVM = sc->addr; cstrSize = sc->size; }
            if (!strcmp(sc->segname, "__TEXT") && !strcmp(sc->sectname, "__objc_methname")) { methVM = sc->addr; methSize = sc->size; }
        }
    }
    // SKU 串区: 已验证 ID 从哪来? 侦查卡 SK verify 结果只在 UI; 引擎层不依赖它 —
    // 改扫 cstring 区找 "com." 开头且含 bundle 主前缀的串(app 自己的 SKU 家族)
    if (!cstrSize) { /* 无 cstring 区(极端) — 跳过 F8v3 */ }
    if (cstrSize) {
        // cstring 区内 SKU 串地址表 + 语义串地址表(一次线性扫)
        #define F8V3_MAXSTR 192
        static uint64_t skuStrVM[F8V3_MAXSTR]; static uint64_t semStrVM[F8V3_MAXSTR];
        int nSku = 0, nSem = 0;
        const char *bundleId = [[[NSBundle mainBundle] bundleIdentifier] UTF8String];
        // 主前缀: com.xxx.yyy → "xxx."(取前两段, 第三段起是产品名)
        char bpre[64] = {0};
        if (bundleId) { strncpy(bpre, bundleId, 63); char *d2 = strchr(bpre, '.'); if (d2 && (d2 = strchr(d2+1, '.'))) *d2 = 0; else bpre[0] = 0; }
        const uint8_t *cb = (const uint8_t *)((uintptr_t)cstrVM + (uintptr_t)slide);
        uint64_t coff = 0;
        while (coff < cstrSize && (nSku < F8V3_MAXSTR || nSem < F8V3_MAXSTR)) {
            const char *s = (const char *)(cb + coff);
            size_t sl = strnlen(s, (size_t)(cstrSize - coff));
            if (sl >= 4 && sl < 96) {
                if (nSku < F8V3_MAXSTR && bpre[0] && !strncmp(s, bpre, strlen(bpre)) && s[strlen(s)-1] != '.')
                    { skuStrVM[nSku++] = cstrVM + coff; }
                else {
                    // v2.58.23: 语义串形态门 — dbg_23 实锤 ServeLog UI 文案
                    // ("No active purchase..."含 purchas)混进 S 集 → 显示层 bl 的基础库
                    // helper fan≥2 全中 → 205 accessor 噪声爆炸(真 oracle 1~3 个)。
                    // 引用串(代码里 adrp+add 指到它)是紧凑 camelCase/点分标识符,
                    // 不是带空格/冒号的句子 — 同 F9 stateKeyShapeOK 判据。
                    BOOL shapeBad = NO;
                    if (memchr(s, ' ', sl) || memchr(s, ':', sl) || memchr(s, '/', sl)) shapeBad = YES;
                    // v2.58.26: 词表改小写不敏感匹配(dbg_25 定谳: ServeLog 驼峰命名
                    // 某状态类字段被 strstr 小写词表全 miss,
                    // S 集归零 → 判定 accessor 段死。yimuliaoran 是小写 URL 串才碰巧命中)
                    if (!shapeBad) {
                        char low2[96];
                        unsigned li = 0;
                        for (; li < sl && li < 95; li++) { char ch = s[li]; low2[li] = (ch >= 'A' && ch <= 'Z') ? ch + 32 : ch; }
                        low2[li] = 0;
                        for (int w = 0; w < 7 && nSem < F8V3_MAXSTR; w++)
                            if (mfStrCaseStr(low2, kSemWords[w])) { semStrVM[nSem++] = cstrVM + coff; break; }
                    }
                }
            }
            coff += sl + 1;
        }
        mfLog(@"[f8v3] 语义串=%d SKU串=%d (前缀%s)", nSem, nSku, bpre[0] ? bpre : "(无)");
        if (nSem >= 2 || nSku >= 1) {
            // ---- ② 引用函数集: __text adrp+add 目标命中串地址 → 函数头 ----
            // 函数头收集(全 __text prologue 扫一次, bsearch 归属)
            #define F8V3_MAXFN 4096
            static uint64_t fnHeads[F8V3_MAXFN]; int nFn = 0;
            for (uint64_t off = 0; off + 4 <= textSize && nFn < F8V3_MAXFN; off += 4) {
                uintptr_t a = (uintptr_t)textVM + (uintptr_t)slide + off;
                uint32_t q = *(const uint32_t *)a;
                if (q == 0xD503237F || ((q & 0x7FC00000) == 0x29800000 && ((q >> 5) & 0x1F) == 31) ||
                    ((q & 0xFFC003FF) == 0xD10003FF && ((q >> 10) & 0xFFF)) ||
                    (q == 0x52800020 && *(const uint32_t *)(a + 4) == 0xD65F03C0))
                    fnHeads[nFn++] = textVM + off;
            }
            if (!nFn) { mfLog(@"[f8v3] 无函数头 — 跳过"); }
            else {
                // bl 全图一次扫: caller头 → 目标头/非头目标(本地函数指针引用是 bl 到非头也记)
                // 只记: caller ∈ 语义/ SKU 引用函数, 目标 ∈ 本地 __text 内非 stub 区
                // 语义引用函数集: bl 扫太重 — 用引用扫(adrp+add)直接归属
                // (每 pc 归属函数头, 集合去重; SKU 集同理)
                uint64_t semFn[F8V3_MAXFN/2]; int nSemFn = 0;
                uint64_t skuFn[F8V3_MAXFN/2]; int nSkuFn = 0;
                for (uint64_t off = 0; off + 16 <= textSize; off += 4) {
                    uintptr_t a = (uintptr_t)textVM + (uintptr_t)slide + off;
                    uint32_t ins1 = *(const uint32_t *)a;
                    if ((ins1 & 0x9F000000) != 0x90000000) continue;
                    int64_t imm = (int64_t)((((ins1 >> 5) & 0x7FFFF) << 2) | ((ins1 >> 29) & 3));
                    if (imm & (1 << 20)) imm -= (int64_t)(1 << 21);
                    uint64_t page = (textVM + off) & ~0xFFFULL;
                    if (imm >= 0) page += (uint64_t)imm << 12; else page -= (uint64_t)(-imm) << 12;
                    // ±4/8/12 窗口找 add imm12
                    uint64_t tgt = 0; BOOL found = NO;
                    for (int d2 = 4; d2 <= 12 && !found; d2 += 4) {
                        uint32_t ins2 = *(const uint32_t *)(a + d2);
                        if ((ins2 & 0xFFC00000) == 0x91000000) {
                            uint64_t add = ((ins2 >> 10) & 0xFFF) << ((ins2 >> 22) & 3);
                            tgt = page + add; found = YES;
                        }
                    }
                    if (!found) continue;
                    BOOL isSem = NO, isSku = NO;
                    for (int k = 0; k < nSem && !isSem; k++) if (semStrVM[k] == tgt) isSem = YES;
                    for (int k = 0; k < nSku && !isSku; k++) if (skuStrVM[k] == tgt) isSku = YES;
                    if (!isSem && !isSku) continue;
                    // pc 归属函数头(线性回溯到最近 prologue — 从 off 向下扫, 遇 prologue 停)
                    uint64_t h = 0;
                    for (int64_t back = 0; back < 0x10000 && off >= (uint64_t)back + 4; back += 4) {
                        uint32_t q = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off - back);
                        if (q == 0xD503237F || ((q & 0x7FC00000) == 0x29800000 && ((q >> 5) & 0x1F) == 31) ||
                            ((q & 0xFFC003FF) == 0xD10003FF && ((q >> 10) & 0xFFF)) ||
                            (q == 0x52800020 && *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off - back + 4) == 0xD65F03C0))
                            { h = textVM + off - back; break; }
                    }
                    if (!h) continue;
                    if (isSem && nSemFn < F8V3_MAXFN/2) {
                        BOOL dup = NO;
                        for (int k = 0; k < nSemFn; k++) if (semFn[k] == h) { dup = YES; break; }
                        if (!dup) semFn[nSemFn++] = h;
                    }
                    if (isSku && nSkuFn < F8V3_MAXFN/2) {
                        BOOL dup = NO;
                        for (int k = 0; k < nSkuFn; k++) if (skuFn[k] == h) { dup = YES; break; }
                        if (!dup) skuFn[nSkuFn++] = h;
                    }
                }
                mfLog(@"[f8v3] 语义引用函数=%d SKU引用函数=%d", nSemFn, nSkuFn);
                // ---- ③ 判定 accessor: S∪W 2 跳 fan 模型(静态预验证 yimuliaoran 收敛) ----
                // 结构实测: 语义显示函数 bl 包装器(选择器) → 包装器 bl 真 accessor。
                // SKU 交叉在数据流单向的 app 上到不了读侧(SKU 写侧独立) — SKU 只当
                // "确有判定"的确认信号。算法: W = S 的 bl 目标(head 元素); 
                // fan(t) = W 中 bl 到 t 的函数数; accessor = fan≥2 且非 W(非中间层)。
                // v2.58.24: 门槛修正 — dbg_24 ServeLog 实锤语义串形态门把纯文案型 app
                // 的 S 集清空(9→0), 旧门 nSemFn≥3 全灭 → 判定 accessor 段不跑, 真信号
                // (尾and 候选)随 S 集一起丢。SKU 函数集(K) 是硬信号(判定必比较 SKU),
                // S∪K 并集进 fan 展开: nSemFn+nSkuFn≥3 且 nSkuFn≥1。
                if (nSemFn + nSkuFn >= 3 && nSkuFn >= 1) {
                    // v2.58.24: S∪K 并集 fan 展开(旧: 仅 S) — K 的 bl 目标同样计 fan
                    int nSK = nSemFn + nSkuFn;
                    static uint64_t skFn[F8V3_MAXFN/2]; int nSKFn = 0;   // S∪K 去重并集
                    for (int i2 = 0; i2 < nSemFn; i2++) skFn[nSKFn++] = semFn[i2];
                    for (int i2 = 0; i2 < nSkuFn; i2++) {
                        BOOL dup = NO;
                        for (int k = 0; k < nSKFn; k++) if (skFn[k] == skuFn[i2]) { dup = YES; break; }
                        if (!dup && nSKFn < F8V3_MAXFN/2) skFn[nSKFn++] = skuFn[i2];
                    }
                    (void)nSK;
                    // v2.58.33: idxOf 改二分 — 实测定谳: 语义函数 192 个,
                    // S∪K bl 扫里每条 bl 都 idxOf(t2) O(nFn=4096) 线性搜 → 4万 bl × 4096
                    // ≈ 1.7亿比较, 侦查卡死在"语义引用函数=192"行后(与 2.58.31 停点相同 —
                    // 形态分类修了, W 展开段的 idxOf 是下一个 O(N×M) 炸弹)。
                    // fnHeads 按地址递增收集, 天然有序 → 二分 O(log 4096)=12 次。
                    int (^idxOf)(uint64_t) = ^int(uint64_t h) {
                        int lo = 0, hi = nFn - 1;
                        while (lo <= hi) {
                            int mid = (lo + hi) >> 1;
                            if (fnHeads[mid] == h) return mid;
                            if (fnHeads[mid] < h) lo = mid + 1; else hi = mid - 1;
                        }
                        return -1;
                    };
                    // S∪K 的 bl 目标 → W(只收 head 元素 — 函数内入口不展开, 会爆)
                    // v2.58.19: S 直调也计 fan(0x1000b8700 直接 bl 真 oracle 的形态)
                    #define F8V3_MAXW 256
                    static uint64_t W[F8V3_MAXW]; int nW = 0;
                    static uint64_t accTgt2[F8V3_MAXW]; static int accFan2[F8V3_MAXW]; int nAcc2 = 0;
                    for (int i2 = 0; i2 < nSKFn; i2++) {
                        uint64_t h = skFn[i2];
                        int hi = idxOf(h);
                        uint64_t end2 = (hi >= 0 && hi + 1 < nFn) ? fnHeads[hi+1] : textVM + textSize;
                        for (uint64_t off2 = h - textVM; off2 + 4 <= end2 - textVM; off2 += 4) {
                            uint32_t ins = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off2);
                            uint32_t op = ins >> 26;
                            if (op != 0x25 && op != 0x05) continue;
                            int64_t imm2 = (int64_t)(ins & 0x3FFFFFF);
                            if (imm2 & (1 << 25)) imm2 -= (int64_t)(1 << 26);
                            uint64_t t2 = textVM + off2 + ((uint64_t)imm2 << 2);
                            if (t2 <= textVM || t2 >= textVM + textSize) continue;
                            if (t2 >= stubVM && t2 < stubVM + stubSize) continue;
                            int sl2 = -1;
                            for (int k = 0; k < nAcc2; k++) if (accTgt2[k] == t2) { sl2 = k; break; }
                            if (sl2 < 0 && nAcc2 < F8V3_MAXW) { accTgt2[nAcc2] = t2; accFan2[nAcc2] = 0; sl2 = nAcc2++; }
                            if (sl2 >= 0) accFan2[sl2]++;
                            if (idxOf(t2) < 0) continue;                    // W 只收 head(可展开)
                            BOOL dup = NO;
                            for (int k = 0; k < nW && !dup; k++) if (W[k] == t2) dup = YES;
                            if (!dup && nW < F8V3_MAXW) W[nW++] = t2;
                        }
                    }
                    // 2 跳 fan: W 中每个 w 的 bl 目标计数(累加进 S 直调的 accTgt2 表)
                    #define F8V3_MAXCAND 256   // v2.58.22: 128→256 对齐 accTgt2 容量(源表 256, 截断丢判定 accessor 风险)
                    static uint64_t accTgt[F8V3_MAXCAND]; static int accFan[F8V3_MAXCAND]; int nAcc = 0;
                    // 先导入 S 直调表(v2.58.19) — 带 F8V3_MAXCAND 截断
                    // v2.58.22 崩溃定谳(ServeLog ips): 此循环曾无界拷贝 accTgt2(≤256)进
                    // accTgt(128) — ServeLog 语义串多, nAcc2>128 越界写踩相邻 __DATA 的
                    // mfLog.logPath/once → dispatch_once 状态损坏 → libdispatch
                    // "Owner in ulock is unknown" brk abort。yimuliaoran nAcc2=31 从未触发。
                    for (int k = 0; k < nAcc2 && nAcc < F8V3_MAXCAND; k++) { accTgt[nAcc] = accTgt2[k]; accFan[nAcc] = accFan2[k]; nAcc++; }
                    for (int iw = 0; iw < nW; iw++) {
                        uint64_t w = W[iw];
                        BOOL isSemFn2 = NO;
                        for (int k = 0; k < nSKFn; k++) if (skFn[k] == w) { isSemFn2 = YES; break; }
                        if (isSemFn2) continue;                              // W ∩ (S∪K) 已计过, 跳过防重复
                        int hi = idxOf(w);
                        uint64_t end2 = (hi >= 0 && hi + 1 < nFn) ? fnHeads[hi+1] : textVM + textSize;
                        for (uint64_t off2 = w - textVM; off2 + 4 <= end2 - textVM; off2 += 4) {
                            uint32_t ins = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off2);
                            uint32_t op = ins >> 26;
                            if (op != 0x25 && op != 0x05) continue;
                            int64_t imm2 = (int64_t)(ins & 0x3FFFFFF);
                            if (imm2 & (1 << 25)) imm2 -= (int64_t)(1 << 26);
                            uint64_t t2 = textVM + off2 + ((uint64_t)imm2 << 2);
                            if (t2 <= textVM || t2 >= textVM + textSize) continue;
                            if (t2 >= stubVM && t2 < stubVM + stubSize) continue;
                            BOOL inW = NO;
                            for (int k = 0; k < nW && !inW; k++) if (W[k] == t2) inW = YES;
                            // v2.58.19: 不再跳过 W 目标 — dbg_19 定谳: 语义函数可
                            // 直接 bl 真 oracle(0x1000b8700→0x1000b81a0), "中间层不收"
                            // 会把 oracle 误标中间层漏掉; 噪声交形态分类器拦(ptr 全滤)
                            int slot2 = -1;
                            for (int k = 0; k < nAcc; k++) if (accTgt[k] == t2) { slot2 = k; break; }
                            if (slot2 < 0 && nAcc < F8V3_MAXCAND) { accTgt[nAcc] = t2; accFan[nAcc] = 0; slot2 = nAcc++; }
                            if (slot2 >= 0) accFan[slot2]++;
                        }
                    }
                    // w 自身的 fan 已由 S 直调计数 — W 循环跳过 W∩S 防双计(isSemFn2 检查已有)
                    // accessor = fan≥2; 排 runtime(取语义函数集最小地址做界 — 
                    // swift/objc 基础库 fan 目标集中在 __text 前段)
                    uint64_t textStartHi = UINT64_MAX;
                    for (int k = 0; k < nSKFn; k++) if (skFn[k] < textStartHi) textStartHi = skFn[k];   // v2.58.24: S∪K
                    // ---- 形态分类(dbg_18 定谳: mov w0,#1 对指针返回型=炸弹) ----
                    // dbg_18: ⚡0x1000a65f0(metadata accessor) → 内购页
                    // 0x1000a796c ldur x22,[x0,#-8] 解引用假指针 1 → 0xfff...f9 崩。
                    // 真 oracle 形态(yimuliaoran 0x1000b81a0): 函数尾 and w0,wN,#1 + ret。
                    // 分类: caller 侧 bl 后 ≤12 条指令内 tst w/cbz/csel(Bool 消费) vs
                    // ldur xN,[x0,#-8](指针消费) — 双信号定返回类型。
                    // (占位行已删 — 分类逻辑在第二遍统一做)
                    // v2.58.19 单遍: 门控(fan≥2 或 fan≥1+bool)+形态分类+输出
                    // v2.58.32: 调用侧形态(ptr/bool)反转循环 — 实测定谳:
                    // 语义引用函数=192(大小写修复后大 app 真实规模) → nAcc 池 256 满 →
                    // 旧"每候选独立全 text 扫 bl 调用点" = 256×textSize/4 ≈ 2.5亿迭代,
                    // 主线程分钟级卡死, 侦查页 4 次全停在同一日志行。改单次全扫+查表,
                    // 复杂度除以 256 — 判定语义不变(ptr/bool 收集口径逐位一致)。
                    static BOOL ptrFlag[F8V3_MAXCAND], boolFlag[F8V3_MAXCAND];
                    memset(ptrFlag, 0, sizeof(ptrFlag)); memset(boolFlag, 0, sizeof(boolFlag));
                    for (uint64_t off3 = 0; off3 + 4 <= textSize; off3 += 4) {
                        uint32_t ins = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off3);
                        uint32_t op = ins >> 26;
                        if (op != 0x25 && op != 0x05) continue;
                        int64_t imm3 = (int64_t)(ins & 0x3FFFFFF);
                        if (imm3 & (1 << 25)) imm3 -= (int64_t)(1 << 26);
                        uint64_t tgt3 = textVM + off3 + ((uint64_t)imm3 << 2);
                        int hit3 = -1;
                        for (int k = 0; k < nAcc; k++) if (accTgt[k] == tgt3) { hit3 = k; break; }
                        if (hit3 < 0 || (ptrFlag[hit3] && boolFlag[hit3])) continue;
                        BOOL ptrV = NO, boolV = NO;
                        for (int step = 1; step <= 6 && off3 + (uint64_t)step * 4 + 4 <= textSize; step++) {
                            uint32_t x = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off3 + (uint64_t)step * 4);
                            if ((x >> 16) == 0xF85F && ((x >> 5) & 0x1F) == 0) { ptrV = YES; break; }
                        }
                        if (!ptrV) for (int step = 1; step <= 24 && off3 + (uint64_t)step * 4 + 4 <= textSize; step++) {
                            uint32_t x = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + off3 + (uint64_t)step * 4);
                            if ((x & 0x7F800000) == 0x72000000 ||
                                (x & 0x7E000000) == 0x34000000 || (x & 0x7E000000) == 0x36000000 ||
                                (x & 0x7FE00C00) == 0x1A800000) { boolV = YES; break; }
                        }
                        if (ptrV) ptrFlag[hit3] = YES;
                        if (boolV) boolFlag[hit3] = YES;
                    }
                    int nShared = 0;
                    for (int k = 0; k < nAcc; k++) {
                        if (accTgt[k] < textStartHi || accFan[k] < 1) continue;
                        BOOL boolTail2 = NO;
                        for (uint64_t b = accTgt[k]; b + 8 <= textVM + textSize && b < accTgt[k] + 0x400; b += 4) {
                            uint32_t x = *(const uint32_t *)((uintptr_t)b + (uintptr_t)slide);
                            if (x == 0xD65F03C0) break;
                            if ((x & 0xFF80001F) == 0x12000000 && ((x >> 5) & 0x1F) != 31) { boolTail2 = YES; break; }
                        }
                        // v2.58.26: ldrb w0,[xN,#imm] 尾判据 — @Observable Bool ivar getter
                        // 形态(dbg_25 ServeLog 静态定谳: hasProSubscription getter 尾
                        // ldrb w0,[x19,#0x10] 后 epilogue+ret, 无 and 无 tst — 旧门全杀)。
                        // ldrb(1 字节加载)本身就是 Bool 返回铁证。
                        BOOL ldrbTail2 = NO;
                        for (uint64_t b = accTgt[k]; b + 8 <= textVM + textSize && b < accTgt[k] + 0x400; b += 4) {
                            uint32_t x = *(const uint32_t *)((uintptr_t)b + (uintptr_t)slide);
                            // ldrb w0,[xN,#imm12]: opcode 0x39400000 + imm12<<10 + Rn<<5 + Rt=0
                            // (掩码只锁 opcode 位段, imm12/Rn 不锁 — 0xFFC003FF 全锁是永假 bug)
                            if ((x & 0xFFC0001F) == 0x39400000) { ldrbTail2 = YES; break; }
                            if (x == 0xD65F03C0) break;
                        }
                        BOOL isPtr2 = ptrFlag[k], isBool2 = boolFlag[k];
                        NSString *shape2 = isPtr2 ? @"ptr" : ((boolTail2 || isBool2) ? @"bool" : @"?");
                        // v2.58.23: 门控重立 — dbg_23 ServeLog 205 accessor 定谳:
                        // 旧门 fan≥2 || shape=bool 在 Swift 上 = 基础库 helper 全中(String
                        // 格式化/enum accessor 被 S 集共享), 真 oracle 1~3 个。
                        // 新门(从严): ptr 杀; (fan≥2 && bool) 收; 尾and 收; 其余杀。
                        // v2.58.34: fan>500 拦 — 实测崩溃定谳(ips: Firebase
                        // worker 线程 _SwiftDeferredNSDictionary 桥接 ldur[x0-8] 解引用
                        // 0xfff...f9 = ptr 型被 mov w0,#1): 192 语义函数大池把 String 桥接/
                        // 格式化 helper 全放进门(fan=13674/2381), 真 oracle 的 fan 天花
                        // 板是几十(显示层函数数), 万级 fan = 基础库铁证。
                        BOOL gateOK = NO;
                        if (![shape2 isEqualToString:@"ptr"] && accFan[k] <= 500) {
                            if (boolTail2) gateOK = YES;                          // 尾 and w0,#1 — 判定尾巴(最稀有)
                            else if (ldrbTail2) gateOK = YES;                     // v2.58.26: ldrb w0 尾 — Bool ivar getter(@Observable 形态)
                            // v2.58.47: 共享 bool 加 fan≤64 门 — dbg_49(HostLog)实锤
                            //   fan=211/41/26/24 无尾巴共享 helper 是 UI/基础库噪声;
                            //   真判定 accessor fan 天花板几十(yimuliaoran 17 调用者)
                            else if (accFan[k] >= 2 && accFan[k] <= 64 && [shape2 isEqualToString:@"bool"]) gateOK = YES;
                        }
                        if (gateOK) {
                            nShared++;
                            mfLog(@"[f8v3] ★判定accessor @%#llx (fan=%d shape=%@ 尾and=%d ldrb尾=%d)", (unsigned long long)accTgt[k], accFan[k], shape2, boolTail2, ldrbTail2);
                            // v2.58.23: score 重立 — 尾and(判定尾巴) > 单纯共享 bool;
                            // top 截断在出栈前统一做(见下), 不在这里堆全量
                            [out addObject:@{
                                @"img": imgName,
                                @"sym": [NSString stringWithFormat:@"@%#llx", (unsigned long long)accTgt[k]],
                                @"vmaddr": @(accTgt[k]),
                                @"slide": @((long)slide),
                                @"score": @((boolTail2 || ldrbTail2) ? ([shape2 isEqualToString:@"bool"] ? 93 : 92) : 91),
                                @"calls": @(accFan[k]),
                                @"shape": shape2,
                            }];
                        }
                    }
                    mfLog(@"[f8v3] 判定 accessor=%d 个 (W=%d)", nShared, nW);
                    // ---- v2.58.26 ④: ivar Bool getter 直扫(@Observable keypath 间接调用
                    // 使 getter 0 个 bl 调用者, fan 模型结构性失明 — dbg_25 ServeLog
                    // 定谳: hasProSubscription getter 0x10009cb58 不在 fan 池但 ldrb w0,
                    // [x19,#0x10]+ret 形态铁证) ----
                    // S∪K 函数体 ldrb/strb [xN,#imm12] imm 收集 = 判定 ivar offset 集;
                    // 全 __text 扫小函数(≤0x200)内「最后一次 w0 写入 = ldrb w0,[xN,#ivarOff]
                    // 且其后 ≤7 条内 ret」= ivar Bool getter。
                    {
                        unsigned char ivHit[64]; memset(ivHit, 0, sizeof(ivHit));
                        int nIvOff = 0;
                        for (int i3 = 0; i3 < nSKFn && nIvOff < 60; i3++) {
                            int hi3 = idxOf(skFn[i3]);
                            if (hi3 < 0) continue;
                            uint64_t end3 = (hi3 + 1 < nFn) ? fnHeads[hi3+1] : textVM + textSize;
                            if (end3 - skFn[i3] > 0x800) continue;
                            for (uint64_t o3 = skFn[i3] - textVM; o3 + 4 <= end3 - textVM; o3 += 4) {
                                uint32_t x = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + o3);
                                if ((x & 0xFFC00000) == 0x39400000 || (x & 0xFFC00000) == 0x39000000) {
                                    unsigned imm12 = (x >> 10) & 0xFFF;
                                    unsigned rn = (x >> 5) & 0x1F;
                                    if (rn != 31 && imm12 > 0 && imm12 < 64 && !ivHit[imm12]) { ivHit[imm12] = 1; nIvOff++; }
                                }
                            }
                        }
                        if (nIvOff >= 1) {
                            if (nIvOff) {
                                char b3[256]; int p3 = 0;
                                for (int q3 = 1; q3 < 64 && p3 < 250; q3++)
                                    if (ivHit[q3]) p3 += snprintf(b3 + p3, (size_t)(250 - p3), "%s%d", p3 ? "/" : "", q3);
                                b3[p3] = 0;
                                mfLog(@"[f8v3] ivar 偏移集 %d 个: %s", nIvOff, b3);
                            }
                            // v2.58.28: 家族距离判据 — offset 16/17/18 太常见, 别的类的
                            // metadata/witness 小函数(0x10011b414 ldur 解引用形态)也会命中
                            // ldrb w0 尾判据 → 早期全崩。真状态类族
                            // getter 与语义函数同族连续(0x10009cbxx-0x10009d7xx),
                            // 距最近 S∪K 函数头 < 0x1000 才收。
                            // v2.58.29: famAnchor 改取语义函数(S)min — dbg_29 实锤:
                            // S∪K 的 min 是 SKU 请求层(0x10001111c, StoreKit 一带),
                            // 与判定类(0x10009cbxx, 另一带)隔 0x8bxxx → 窗口全杀真 getter
                            // (ivar Bool getter=0)。语义函数才是判定类同族锚。
                            uint64_t famAnchor = UINT64_MAX;
                            for (int i4 = 0; i4 < nSemFn; i4++) if (semFn[i4] < famAnchor) famAnchor = semFn[i4];
                            int nGetter = 0;
                            for (int fi = 0; fi < nFn && nGetter < 8; fi++) {
                                uint64_t gh = fnHeads[fi];
                                uint64_t gend = (fi + 1 < nFn) ? fnHeads[fi+1] : textVM + textSize;
                                if (gend - gh > 0x200 || gend - gh < 0x20) continue;
                                if (famAnchor != UINT64_MAX && (gh < famAnchor ? famAnchor - gh : gh - famAnchor) > 0x1000) continue;   // v2.58.28: 家族窗口(双向 — 真 getter 可能在语义函数前, dbg_26: 0x10009cb58 < 0x10009cc70)
                                uint64_t lastLdrb = 0; unsigned lastImm = 0;
                                for (uint64_t o3 = gh - textVM; o3 + 4 <= gend - textVM; o3 += 4) {
                                    uint32_t x = *(const uint32_t *)((uintptr_t)textVM + (uintptr_t)slide + o3);
                                    if ((x & 0xFFC0001F) == 0x39400000) {          // ldrb w0,[xN,#imm12]
                                        unsigned imm12 = (x >> 10) & 0xFFF;
                                        unsigned rn = (x >> 5) & 0x1F;
                                        if (rn != 31 && imm12 < 64 && ivHit[imm12]) { lastLdrb = textVM + o3; lastImm = imm12; }
                                    }
                                }
                                if (!lastLdrb) continue;
                                BOOL retNear = NO;
                                for (int d3 = 4; d3 <= 28; d3 += 4) {
                                    uint64_t aa = lastLdrb + d3;
                                    if (aa + 4 > textVM + textSize) break;
                                    uint32_t y = *(const uint32_t *)((uintptr_t)aa + (uintptr_t)slide);
                                    if (y == 0xD65F03C0) { retNear = YES; break; }
                                }
                                if (retNear) {
                                    nGetter++;
                                    // v2.58.28: patch 点 = ldrb 指令本身(不是函数头) — dbg_27 实锤:
                                    // @Observable 宏 getter 内联 registrar.access(), patch 头跳过 access
                                    // → SwiftUI 观察链断 → 全崩。改单指令: ldrb w<Rt>,#ivar → mov w<Rt>,#1,
                                    // 函数结构保留(registrar 照跑), 只把读值恒真。
                                    uint32_t orig = *(const uint32_t *)((uintptr_t)lastLdrb + (uintptr_t)slide);
                                    unsigned rt = orig & 0x1F;
                                    mfLog(@"[f8v3] ★ivarRead @%#llx (off=0x%x Rt=w%u size=%#llx fn@%#llx)", (unsigned long long)lastLdrb, lastImm, rt, (unsigned long long)(gend-gh), (unsigned long long)gh);
                                    [out addObject:@{
                                        @"img": imgName,
                                        @"sym": [NSString stringWithFormat:@"ivarRead@0x%x.%u", lastImm, rt],
                                        @"vmaddr": @(lastLdrb),
                                        @"slide": @((long)slide),
                                        @"score": @(94),
                                        @"calls": @(0),
                                        @"shape": @"bool",
                                    }];
                                }
                            }
                            mfLog(@"[f8v3] ivar Bool getter=%d 个", nGetter);
                        }
                    }
                    // ============================================================
                    // v2.58.40: F10 深槽字段装载链(静态可行已三样本实证 — 真目标
                    // 0x14211bc 回归命中, Blink×3 构建逐点恒差-8 对齐, 61→3 收敛零噪声)。
                    // 算法(deepslot_fast.py 同款):
                    //   L1 深槽ldur→str[reg]: LDUR Xt,[x29,#-imm9] imm9∈[0xC0,0x180)
                    //       (w>>22)==0x3E1 && Rn==x29 && opc==0, imm9 在 bits20-12(勿用低9位!)
                    //       + 后4条内 STR Xt,[Xn,Xm] reg-offset ((w>>22)==0x3E0)
                    //   L2 宿主函数的 bl caller ∈ 语义函数 + 闭包归并(caller 段无词表串
                    //       时 0x8000 内向外层函数头回溯 — Swift async 闭包 outline 假头,
                    //       实测: 闭包假头→外层语义函数 归并)
                    //   L3 caller bl 前 0x30 内 LDRSW ((w>>22)==0x2E6) 反射 witness 装载
                    // 语义串词表(RC 型): 与 F8v3 共用 cstring 扫, 深槽专属词表补
                    //   customerinfo/receipt/verific/licens(F8v3 词表无这四个)
                    // 与 F8 互补: F8=fan≥2 多路 accessor(Bool getter 判型);
                    //   深槽链=单 fan 语义下游字段装载(RC 序列化判型)。
                    // ============================================================
                    {
                        // ① 深槽词表串地址表(cstring 区一次线性扫, 与上面 semStrVM 分开)
                        static const char *kDSWords[] = { "entitle", "subscri", "licens", "customerinfo", "receipt", "verific" };
                        #define F10_MAXSTR 256
                        static uint64_t dsStrVM[F10_MAXSTR]; int nDsStr = 0;
                        const uint8_t *cb2 = (const uint8_t *)((uintptr_t)cstrVM + (uintptr_t)slide);
                        uint64_t c2 = 0;
                        while (c2 < cstrSize && nDsStr < F10_MAXSTR) {
                            const char *s = (const char *)(cb2 + c2);
                            size_t sl = strnlen(s, (size_t)(cstrSize - c2));
                            if (sl >= 6 && sl < 96) {
                                char low3[96]; unsigned li3 = 0;
                                for (; li3 < sl && li3 < 95; li3++) { char ch = s[li3]; low3[li3] = (ch >= 'A' && ch <= 'Z') ? ch + 32 : ch; }
                                low3[li3] = 0;
                                for (int w = 0; w < 6; w++)
                                    if (strstr(low3, kDSWords[w])) { dsStrVM[nDsStr++] = cstrVM + c2; break; }
                            }
                            c2 += sl + 1;
                        }
                        if (nDsStr >= 2) {
                            mfLog(@"[f10] 深槽语义串=%d", nDsStr);
                            // ② 深槽语义函数集(adrp+add 目标命中 → 函数头归属, 与 F8v3 同法但独立集)
                            #define F10_MAXFN 2048
                            static uint64_t dsSemFn[F10_MAXFN]; int nDsSemFn = 0;
                            for (uint64_t off = 0; off + 16 <= textSize && nDsSemFn < F10_MAXFN; off += 4) {
                                uintptr_t a = (uintptr_t)textVM + (uintptr_t)slide + off;
                                uint32_t ins1 = *(const uint32_t *)a;
                                if ((ins1 & 0x9F000000) != 0x90000000) continue;
                                int64_t imm = (int64_t)((((ins1 >> 5) & 0x7FFFF) << 2) | ((ins1 >> 29) & 3));
                                if (imm & (1 << 20)) imm -= (int64_t)(1 << 21);
                                uint64_t page = (textVM + off) & ~0xFFFULL;
                                if (imm >= 0) page += (uint64_t)imm << 12; else page -= (uint64_t)(-imm) << 12;
                                uint64_t tgt = 0; BOOL found = NO;
                                for (int d2 = 4; d2 <= 12 && !found; d2 += 4) {
                                    uint32_t ins2 = *(const uint32_t *)(a + d2);
                                    if ((ins2 & 0xFFC00000) == 0x91000000) {
                                        uint64_t add = ((ins2 >> 10) & 0xFFF) << ((ins2 >> 22) & 3);
                                        tgt = page + add; found = YES;
                                    }
                                }
                                if (!found) continue;
                                BOOL hit = NO;
                                for (int k = 0; k < nDsStr && !hit; k++) if (dsStrVM[k] == tgt) hit = YES;
                                if (!hit) continue;
                                uint64_t h = 0;
                                for (int64_t back = 0; back < 0x10000 && off >= (uint64_t)back + 12; back += 4) {
                                    uintptr_t qa = (uintptr_t)textVM + (uintptr_t)slide + off - back;
                                    uint32_t q = *(const uint32_t *)qa;
                                    if ((q & 0x7FC00000) != 0x29800000 || ((q >> 5) & 0x1F) != 31) continue;
                                    for (int d3 = 4; d3 <= 32; d3 += 4) {
                                        uint32_t q2 = *(const uint32_t *)(qa + d3);
                                        if ((q2 & 0xFFC003FF) == 0x910003FD) { h = textVM + off - back; break; }   // v2.58.42: 无 slide 口径(与 F8v3 fnHeads 同)
                                    }
                                    if (h) break;
                                }
                                if (!h) continue;
                                BOOL dup = NO;
                                for (int k = 0; k < nDsSemFn; k++) if (dsSemFn[k] == h) { dup = YES; break; }
                                if (!dup) dsSemFn[nDsSemFn++] = h;
                            }
                            mfLog(@"[f10] 深槽语义函数=%d", nDsSemFn);
                            if (nDsSemFn >= 1) {
                                // ③ L1 深槽点收集(LDUR 深槽 + 后4条内 STR reg-offset 同寄存器)
                                //    + 宿主函数归属(bsearch fnHeads — F8v3 已收集, 有序)
                                #define F10_MAXPT 2048
                                static uint64_t dsPts[F10_MAXPT]; int nDsPts = 0;
                                static uint64_t dsHost[F10_MAXPT];   // 每点的宿主函数头
                                static uint32_t dsPtRt[F10_MAXPT];    // v2.58.40.1: LDUR 目标寄存器(跨 app 正确性 — 不一定是 x9)
                                // v2.58.41: prologue 紧判据(dbg_42 定谳 0 命中根因) —
                                //   C 版宽判据(含 sub sp/nop)回溯停在 prologue 中间(0x14208e8),
                                //   真函数头 0x14208cc 反而漏掉 → 宿主归属错 → L2 全 miss。
                                //   紧判据 = Python 版同款: stp 任意对 pre-index 到 sp + 8条内 add x29,sp。
                                // v2.58.44: L1 形态判定改读磁盘文件原始字节 — dbg_45 定谳:
                                //   INLINE-PATCH(2.58.39 定版资产)在 ctor 已把真点 0x14211bc
                                //   运行时改写为 mov x9,#1(0xd2800029), 运行时内存读不到原始
                                //   ldur → 真点隐形, 只剩未被 patch 的 0x11d5398 命中(点位不对)。
                                //   磁盘文件不受运行时 patch 影响, 读文件 = 读原始指令。
                                NSData *f10exe = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:mainPath] options:NSDataReadingMappedIfSafe error:NULL];
                                const uint8_t *f10p = f10exe.bytes;
                                BOOL f10fileOK = (f10p != NULL && (uint64_t)f10exe.length >= textFileOff + textSize);
                                if (!f10fileOK)
                                    mfLog(@"[f10] 主二进制文件读取失败(len=%lu need=%llu) — L1 用运行时内存", (unsigned long)f10exe.length, (unsigned long long)(textFileOff + textSize));
                                for (uint64_t off = 0; off + 20 <= textSize && nDsPts < F10_MAXPT; off += 4) {
                                    uintptr_t a = (uintptr_t)textVM + (uintptr_t)slide + off;
                                    uint32_t w1 = f10fileOK ? *(const uint32_t *)(f10p + textFileOff + off)
                                                             : *(const uint32_t *)a;
                                    if ((w1 >> 22) != 0x3E1) continue;              // LDUR 64
                                    if (((w1 >> 5) & 0x1F) != 29) continue;            // x29
                                    if (((w1 >> 10) & 3) != 0) continue;               // opc=00
                                    uint32_t imm9 = (w1 >> 12) & 0x1FF;                // bits20-12!
                                    if (imm9 < 0xC0 || imm9 >= 0x180) continue;       // 深槽窗口
                                    uint32_t xt = w1 & 0x1F;
                                    BOOL store = NO; uint32_t rm = 0;
                                    for (int j = 1; j <= 4 && !store; j++) {
                                        uint32_t w2 = f10fileOK ? *(const uint32_t *)(f10p + textFileOff + off + j * 4)
                                                                 : *(const uint32_t *)(a + j * 4);
                                        // v2.58.43: STR reg-offset 与 STUR 同顶10位(0x3E0),
                                        //   分水岭 = bits11-10: STR=10, STUR=00。旧版漏判把
                                        //   "ldur→stur 帧槽暂存"当字段装载(dbg_44 三点位错)。
                                        if ((w2 >> 22) == 0x3E0 && ((w2 >> 10) & 3) == 2 && (w2 & 0x1F) == xt) {
                                            store = YES;
                                            rm = (w2 >> 16) & 0x1F;   // STR 的偏移寄存器
                                        }
                                    }
                                    if (!store) continue;
                                    // v2.58.43: 偏移寄存器必须来自 adrp+ldr 偏移表(直接结构字段写),
                                    //   排除 ldrsw witness 反射写(0x1420f60 案)与 ldur 深槽混用(0x12e17e0 案)
                                    //   真点 0x14211bc: ldr x8,[x8,#0x878] → ldur → str x9,[x0,x8]
                                    //   查 ldur 前 8 字节与后 4 字节窗口(排除 ldur 自身)
                                    BOOL offTbl = NO;
                                    if (off >= 8) {
                                        for (int64_t back2 = 4; back2 <= 8 && !offTbl; back2 += 4) {
                                            uint32_t qm = f10fileOK ? *(const uint32_t *)(f10p + textFileOff + off - back2)
                                                                     : *(const uint32_t *)(a - back2);
                                            if ((qm & 0xFFC00000) == 0xF9400000 && (qm & 0x1F) == rm) offTbl = YES;   // ldr Xt,[Xn,#imm12]
                                        }
                                    }
                                    if (!offTbl) {
                                        for (int f2 = 4; f2 <= 8 && !offTbl; f2 += 4) {
                                            uint32_t qm = f10fileOK ? *(const uint32_t *)(f10p + textFileOff + off + f2)
                                                                     : *(const uint32_t *)(a + f2);
                                            if ((qm & 0xFFC00000) == 0xF9400000 && (qm & 0x1F) == rm) offTbl = YES;
                                        }
                                    }
                                    if (!offTbl) continue;
                                    // 宿主函数头: 紧判据回溯(stp 预索引 + 8条内 add x29,sp)
                                    uint64_t h = 0;
                                    for (int64_t back = 0; back < 0x8000 && off >= (uint64_t)back + 12; back += 4) {
                                        uintptr_t qa = (uintptr_t)textVM + (uintptr_t)slide + off - back;
                                        uint32_t q = *(const uint32_t *)qa;
                                        if ((q & 0x7FC00000) != 0x29800000 || ((q >> 5) & 0x1F) != 31) continue;
                                        for (int d3 = 4; d3 <= 32; d3 += 4) {
                                            uint32_t q2 = *(const uint32_t *)(qa + d3);
                                            if ((q2 & 0xFFC003FF) == 0x910003FD) { h = textVM + off - back; break; }   // v2.58.42: 无 slide 口径
                                        }
                                        if (h) break;
                                    }
                                    if (h) { dsPts[nDsPts] = textVM + off; dsHost[nDsPts] = h; dsPtRt[nDsPts] = xt; nDsPts++; }
                                }
                                mfLog(@"[f10] L1 深槽点=%d", nDsPts);
                                // ④ L2: 宿主函数的 bl caller ∈ 深槽语义函数(含闭包归并 0x8000)
                                //    ⑤ L3: caller bl 前 0x30 内 LDRSW → 终命中
                                // bl 全图扫一次: 只记 (目标=宿主, caller) 对
                                int nDS10 = 0;
                                for (uint64_t off = 0; off + 4 <= textSize && nDS10 < 32; off += 4) {
                                    uintptr_t a = (uintptr_t)textVM + (uintptr_t)slide + off;
                                    uint32_t wb = *(const uint32_t *)a;
                                    if ((wb & 0xFC000000) != 0x94000000) continue;    // bl
                                    int64_t imm26 = (int64_t)(wb & 0x3FFFFFF);
                                    if (imm26 & (1 << 25)) imm26 -= (1 << 26);
                                    uint64_t tgt = textVM + off + ((uint64_t)imm26 << 2);
                                    BOOL isHost = NO;
                                    for (int k = 0; k < nDsPts; k++) if (dsHost[k] == tgt) { isHost = YES; break; }
                                    if (!isHost) continue;
                                    // caller 函数头(紧判据, 无 slide 口径)
                                    uint64_t cf = 0;
                                    for (int64_t back = 0; back < 0x10000 && off >= (uint64_t)back + 12; back += 4) {
                                        uintptr_t qa = (uintptr_t)textVM + (uintptr_t)slide + off - back;
                                        uint32_t q = *(const uint32_t *)qa;
                                        if ((q & 0x7FC00000) != 0x29800000 || ((q >> 5) & 0x1F) != 31) continue;
                                        for (int d3 = 4; d3 <= 32; d3 += 4) {
                                            uint32_t q2 = *(const uint32_t *)(qa + d3);
                                            if ((q2 & 0xFFC003FF) == 0x910003FD) { cf = textVM + off - back; break; }
                                        }
                                        if (cf) break;
                                    }
                                    if (!cf) continue;
                                    // 语义判定 + 闭包归并(0x8000 总跨度内向外层回溯, 深 32 层 — 大函数夹 10 假头, 8 层不够)
                                    BOOL sem = NO;
                                    uint64_t cf2 = cf;
                                    for (int depth = 0; depth < 32 && !sem; depth++) {
                                        for (int k = 0; k < nDsSemFn; k++) if (dsSemFn[k] == cf2) { sem = YES; break; }
                                        if (sem) break;
                                        if (cf - cf2 > 0x8000) break;   // 总跨度上限
                                        // 向外层函数头回溯(紧判据, 无 slide 口径, 从 cf2 向下找最近函数头)
                                        uint64_t outer = 0;
                                        for (int64_t back = 4; back < 0x8000; back += 4) {
                                            if (cf2 - textVM < (uint64_t)back + 12) break;
                                            uintptr_t qa = (uintptr_t)textVM + (uintptr_t)slide + (cf2 - textVM) - back;
                                            uint32_t q = *(const uint32_t *)qa;
                                            if ((q & 0x7FC00000) != 0x29800000 || ((q >> 5) & 0x1F) != 31) continue;
                                            for (int d3 = 4; d3 <= 32; d3 += 4) {
                                                uint32_t q2 = *(const uint32_t *)(qa + d3);
                                                if ((q2 & 0xFFC003FF) == 0x910003FD) { outer = cf2 - back; break; }
                                            }
                                            if (outer) break;
                                        }
                                        if (!outer || cf2 - outer > 0x8000) break;
                                        cf2 = outer;
                                    }
                                    if (!sem) continue;
                                    // L3: bl 前 0x30 内 LDRSW ((w>>22)==0x2E6)
                                    BOOL ldrsw = NO;
                                    for (int64_t k = 4; k <= 0x30 && !ldrsw; k += 4) {
                                        if (off < (uint64_t)k) break;
                                        uint32_t w3 = *(const uint32_t *)(a - k);
                                        if ((w3 >> 22) == 0x2E6) ldrsw = YES;
                                    }
                                    if (!ldrsw) continue;
                                    // 命中: 宿主函数里挑该函数的深槽点(第一个)入库
                                    uint64_t pt = 0; uint32_t ptRt = 9;
                                    for (int k = 0; k < nDsPts; k++) if (dsHost[k] == tgt) { pt = dsPts[k]; ptRt = dsPtRt[k]; break; }
                                    if (!pt) continue;
                                    nDS10++;
                                    mfLog(@"[f10] ★深槽装载点 @%#llx x%u (host=%#llx caller=%#llx)", (unsigned long long)pt, ptRt, (unsigned long long)tgt, (unsigned long long)cf);
                                    [out addObject:@{
                                        @"img": imgName,
                                        @"sym": [NSString stringWithFormat:@"deepslot@%llx.%u", (unsigned long long)(pt - textVM), ptRt],
                                        @"vmaddr": @(pt),
                                        @"slide": @((long)slide),
                                        @"score": @(93),
                                        @"calls": @(0),
                                        @"shape": @"deepslot",
                                    }];
                                }
                                mfLog(@"[f10] 深槽装载点=%d 个", nDS10);
                            }
                        }
                    }
                    // v2.58.23: score 排序 + top12 截断 — dbg_23 定谳 205 个全量
                    // 入 entDumps 是噪声倾倒(真 oracle 1~3 个)。排序: score↓ → fan↓
                    // (f8v2 的 out 在此 return 前已 top12, 这里只截 f8v3 追加段)
                    // v2.58.76 修(f8v2_78 定谳): 旧实现把 f8v2 段(score 0~8)与 f8v3 段
                    //   (score 91~93)混在一个数组里全局排序 + 统一截 12 → 两把不同刻度的尺子
                    //   相比, f8v2 语义锚定候选(调用过 currentEntitlements/productID 的真候选)
                    //   **整段被压到底部截掉**, 用户看到的 12 点全是 f8v3 共享 bool getter 噪声。
                    //   (旧注释自述"只截 f8v3 追加段", 实现却截整体 — 注释与代码不符)
                    //   修法: f8v2 段中 score≥3(语义锚定: CE/productID/updates/Transactions)
                    //   保位; f8v3 只填剩余槽位。
                    if ([out isKindOfClass:[NSMutableArray class]]) {
                        NSMutableArray *mo = (NSMutableArray *)out;
                        NSMutableArray *keep = [NSMutableArray array];
                        NSMutableArray *pool = [NSMutableArray array];
                        for (NSUInteger i = 0; i < mo.count; i++) {
                            NSDictionary *it = mo[i];
                            // v2.58.174 根因修复(dbg_161/162 "判定点腿飞了"): deepslot(F10 深槽判定点腿)
                            //   无条件保位。deepslot 在 f8v2Seg 之后加入, 旧逻辑归 pool; 当语义锚定候选≥4
                            //   时 room=0 → pool 一个不填 → F10 判定点腿(reflix 0x14211bc/0x11d5398)被
                            //   当噪声截断丢弃。deepslot 是 F10 专属强判定点(score93, 云型双因子的本地腿),
                            //   与 f8v3 共享 getter 噪声不同类, 绝不能进 pool 参与截断。
                            if ([it[@"shape"] isEqualToString:@"deepslot"] || (i < f8v2Seg && [it[@"score"] intValue] >= 3)) [keep addObject:it];
                            else [pool addObject:it];
                        }
                        [pool sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                            // v2.58.27: 方向修正 — 旧写法 d<0?Descending:Ascending 把高分排到尾部,
                            // top12 removeLast 恰好删掉 ivarBoolGetter(94)真判定层, dbg_26 实锤
                            int d = [b[@"score"] intValue] - [a[@"score"] intValue];
                            if (d) return d < 0 ? NSOrderedAscending : NSOrderedDescending;
                            // v2.58.47: 并列改 calls 升序 — dbg_49(HostLog)实锤: 91分共享bool
                            //   按 calls 降序补位 = fan=211/41/26/24 基础库 helper 混进 top12;
                            //   判定函数调用点少, UI/基础库 helper 调用点多(与 F8v2 内部排序同原则)
                            int c = [a[@"calls"] intValue] - [b[@"calls"] intValue];
                            return c < 0 ? NSOrderedAscending : NSOrderedDescending;
                        }];
                        // v2.58.77: 有语义锚定就不再用噪声填满 12 — 旧行为(keep=4+fill=8)
                        //   让卡片报"12 个", 用户看着像真有 12 个候选(dbg_79)。
                        //   语义 ≥4 → 不填; 语义 1~3 → 补到 4; 语义 0 → 兜底填满(纯 getter app)
                        NSUInteger target = keep.count == 0 ? 12 : (keep.count >= 4 ? keep.count : 4);
                        NSUInteger room = target > keep.count ? target - keep.count : 0;
                        NSUInteger fill = MIN(pool.count, room);
                        [mo removeAllObjects];
                        [mo addObjectsFromArray:keep];
                        [mo addObjectsFromArray:[pool subarrayWithRange:NSMakeRange(0, fill)]];
                        NSUInteger nDeepKept = 0;
                        for (NSDictionary *it in keep) if ([it[@"shape"] isEqualToString:@"deepslot"]) nDeepKept++;
                        mfLog(@"[f8v3] 截断: 语义锚定保位=%lu 槽(含 F10 深槽 %lu), getter 填充=%lu (池 %lu)",
                              (unsigned long)keep.count, (unsigned long)nDeepKept, (unsigned long)fill, (unsigned long)pool.count);
                    }
                }
            }
        }
    }
    } // @autoreleasepool F8v3
    return @{@"cands": out, @"ncalls": @(nCall), @"skstubs": @(nSkStub), @"skimports": @(nSkStub),
             @"sk2pts": sk2pts};
    }
}

NSDictionary *mfReconFingerprint(void) {
    __block NSArray *stateKeys = @[];   // v2.58.35: 提升函数级 — lines 块内采集, verdict 判型/return 都要用
    // v2.58.120: 分段进度日志 — dbg_113 定谳: scripting 上侦查卡空白(recon 未跑完),
    //   但旧实现全程无进度输出, 无法定位卡在哪一段。现在每个大段入口打一行, 下次日志一次定位。
    //   命名 reconP (progress) 便于 grep; 不影响 UI/判型。
    #define RECON_P(seg) mfLog(@"[reconP] %s", seg)
    RECON_P("enter");

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
        // mach=1 说明有本地许可服务器在场(样本型); vmprot=1 说明有内联补丁动作
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
    RECON_P("F3-excports");
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
                // 目标型强指纹: 独立 BREAKPOINT 条目 + MACH_EXCEPTION_CODES|EXCEPTION_STATE + ARM_THREAD_STATE64
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
        // v2.58 定位修正(用户判定): EXCPORTS=检测"别家 mach 许可服务器"的观察判据(样本型),
        //   不是本插件 patch 流程的一环 — 只在 mach 命中时作为旁证输出, 不再当主判定展示。
    }

    // ---- F4 网络捕获域命中(自家探针流量剔除 — mfprobe offerings 是我们发的, 算自证) ----
    RECON_P("F4-netcapture");
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
    RECON_P("F6-skform-enter");
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
                                    [scanBlobs addObject:[NSData dataWithBytesNoCopy:(void *)(uintptr_t)(sects[s].addr + (uint64_t)slide) length:(NSUInteger)sects[s].size freeWhenDone:NO]];   // v2.58.120: 零拷贝 — 深拷贝在数百框架的 app(scripting)上累计数 GB → recon 卡死(dbg_113)
                                    blobBytes += sects[s].size;
                                }
                            }
                        }
                    } else if (lc->cmd == LC_SYMTAB) {
                        strsize = ((const struct symtab_command *)lc)->strsize;
                        if (strsize) [scanBlobs addObject:[NSData dataWithBytesNoCopy:(void *)((const uint8_t *)h + ((const struct symtab_command *)lc)->stroff + lDelta) length:strsize freeWhenDone:NO]];   // v2.58.120: 零拷贝(同上)
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
    RECON_P("F6-skform-done");
    // v2.58.55: F8v2 扫描提升到框架块之前 — sk2LocalType 抑制判据需要 sk2pts(单一调用点)
    RECON_P("F8v2-enter");
    NSDictionary *f8v2 = mfReconF8v2Scan();
    RECON_P("F8v2-done");
    NSArray *cands = f8v2[@"cands"];
    NSArray *sk2pts = f8v2[@"sk2pts"];
    BOOL sk2LocalType = NO;
    {
        NSUInteger nS = 0;
        for (NSDictionary *f in sk2pts) if ([f[@"shape"] isEqualToString:@"sk2pro"] || [f[@"shape"] isEqualToString:@"sk2get"] || [f[@"shape"] isEqualToString:@"sk2br"] || [f[@"shape"] isEqualToString:@"sk2vfy"]
                ) nS++;
        if (!cloudBrands.count && !mach && nS >= 1 &&
            (mfRecFind(p, n, "verification failed") || mfRecFind(p, n, "could not be verified") || mfRecFind(p, n, "snapshot verification")))
            sk2LocalType = YES;
    }
    // F11 自研服务端权益型(v2.58.75, bplayer 案定谳): app 自带 IAP 端点(/iap/pro-status
    //   /iap/transactions 等) → 权益状态由**自家后端**下发, 本地只有 Codable 解码后的镜像字段
    //   (无代码引用=纯反射串) + 容器 Preferences 为空 → 指令级 patch 到不了判定链。
    //   判据: ①自研 /iap/* 端点 ≥1 条 ②有 VIP/权益类 Codable 字段(纯反射) ③无云 SDK 品牌
    //   → 判决「服务端权威」并跳过入库(服务端权威 app 本地判定点无意义, 判型总闸拦下)。
    //   注: 提前到此计算 — merge 抑制(下方)与 verdict(末尾)都要用, 单一事实来源。
    //   v2.58.76 修正(用户定案): 旧判据用 vip_info/vip_type/vipStatus 当"权益 Codable 字段"
    //   是错的 — 那些是**百度/115 网盘** API 字段(邻居 baidu_name/netdisk_name/rt_space_info),
    //   与 Pro 无关。bplayer 实测: 4 个 Pro SKU 全在二进制, 设备 plist 零 Pro 状态键
    //   → Pro 是运行时由 StoreKit 算的**本地链**, 不是服务端下发。
    //   新判据加**本地 SK 链否决**: 只要本地 SK2 消费链在场(SK 形态 + 无锚/有锚点位),
    //   权益判定就落在本地, 绝不判"服务端权威"。
    BOOL srvSelfIap = NO;
    BOOL srvTicket = NO;   // v2.58.124: 服务器授权票据型(块内赋值, 函数级作用域 — verdict 链要用)
    {
        static NSArray *kIapPaths;
        static dispatch_once_t onceIap;
        dispatch_once(&onceIap, ^{
            kIapPaths = @[@"/iap/pro-status", @"/iap/transactions", @"/iap/verify",
                          @"/iap/status", @"/iap/entitlement", @"/iap/subscription"];
        });
        int epHits = 0;
        for (NSString *pp in kIapPaths) if (mfRecFind(p, n, pp.UTF8String)) epHits++;
        NSUInteger nLocalPts = 0;
        for (NSDictionary *f in sk2pts) {
            NSString *sh = f[@"shape"] ?: @"";
            if ([sh isEqualToString:@"sk2pro"] || [sh isEqualToString:@"sk2get"]
                || [sh isEqualToString:@"deepslot"]) nLocalPts++;
        }
        // v2.58.116: 加 sk2vfy 也计入本地链(它是 SK2 验证判定门, 属本地判定)
        NSUInteger nVfyPts = 0;
        for (NSDictionary *f in sk2pts)
            if ([f[@"shape"] isEqualToString:@"sk2vfy"]) nVfyPts++;
        BOOL skHere = ([skType containsString:@"SK"] && (nLocalPts > 0 || nVfyPts > 0));
        // v2.58.124 (dbg_117 定谳): 服务器授权票据型 — target-app 案。
        //   实测证据: 30 个 sk2vfy 门全 patch(含权益锚定门 0x2361364 + 双守卫组),
        //   字节全落地但 UI 不亮。二进制深挖找到协议结构:
        //     CommunityV2EntitlementSyncRequestDTO { current_entitlements, app_transaction_id,
        //                                            signed_app_transaction }
        //     响应状态机: serviceUnavailable/unauthorized/rejected/noEntitlement/invalidLease/
        //                 authorized/superseded/platformAuth/invalidResponse
        //     票据字段: principal_id, device_id, app_transaction_id, features, iat, exp,
        //               grace_seconds, kid, source, app_environment  ← JWT 标准字段!
        //     本地缓存: verifiedAppStoreIdentity.cachedDecision.blocked.production
        //     ★ permanent_entitlements_authoritative  ← 服务器明确标记"以服务器为准"
        //   → 权益 = 服务器签发 JWT 票据 + 本地验票; 本地 StoreKit 结果只作为**上报输入**,
        //     不作为判定依据。本地 patch 结构性无效(与 bplayer 遥测型有本质区别)。
        //   判据: 票据字段族(iat+exp+grace_seconds+kid) + entitlements:sync 端点
        //         + permanent_entitlements_authoritative 串, 三者任一命中即判。
        // (v2.58.124: 已提升到函数级)
        {
            int ticketHits = 0;
            if (mfRecFind(p, n, "entitlements:sync")) ticketHits += 2;
            if (mfRecFind(p, n, "permanent_entitlements_authoritative")) ticketHits += 2;
            if (mfRecFind(p, n, "grace_seconds")) ticketHits++;
            if (mfRecFind(p, n, "app_transaction_id")) ticketHits++;
            if (mfRecFind(p, n, "entitlement_scope")) ticketHits++;
            if (mfRecFind(p, n, "verifiedStoreKitProSnapshot")) ticketHits++;
            if (ticketHits >= 3) srvTicket = YES;
        }
        if (!cloudBrands.count && !mach && epHits >= 1 && !skHere) {
            srvSelfIap = YES;
            [lines addObject:[NSString stringWithFormat:
                @"自研 IAP 端点 %d 条 + 无本地 SK 权益链 → 权益状态由自家后端下发", epHits]];
        } else if (srvTicket) {
            // v2.58.124: 服务器授权票据型 — 优先于"本地判定型"播报(结构性结论)
            [lines addObject:@"服务器授权票据型(entitlements:sync 端点 + JWT 票据字段 iat/exp/kid/grace_seconds"
                             @" + permanent_entitlements_authoritative) — 权益=服务器签发票据, 本地 patch 结构性无效"];
        } else if (epHits >= 1 && skHere) {
            // v2.58.116 (抓包实证修正): 用户提供解锁后抓包 — POST /iap/pro-status 响应
            //   在解锁前后**完全一致**({"active":false}), 而 UI/恢复购买/功能三项全通。
            //   → 服务端响应不是判定源, 端点只是**遥测/数据同步**。
            //   旧文案"混合型, 以本地 StoreKit 判定为准"会误导(暗示服务端有话语权);
            //   实际: 权益 100% 本地判定, 服务端端点与解锁无关。
            [lines addObject:[NSString stringWithFormat:
                @"自研 IAP 端点 %d 条 + 本地 SK 权益链在场(%lu 门) → 本地判定型(端点仅遥测, 实测响应不影响 UI)",
                epHits, (unsigned long)(nLocalPts + nVfyPts)]];
        }
    }
    // ══════════ v2.58.169 判型总闸(第一刀: 前置入库闸门) ══════════
    // 病(dbg_155): 框架扫描/sk2/cands 的 merge 全在判型之前跑, verdict 最后才算, 管不住入库
    //   → mailnow 被塞 3 个 SwiftyStoreKit 内部点(needsFinishTransaction, 非 Pro 门)。
    // 治: 把"本地代码点无意义"的判型信号提到所有 merge 之前, 一个闸门 gBlockCodePts 统管:
    //   服务端票据/自研服务端 + 运行时观测确证的收据验证型(购买流消费者/收据验证类) →
    //   本地指令 patch 结构性无效, 一个点都不入库(杜绝"什么都往 patch 引擎塞")。
    //   信号全部就绪: srvTicket/srvSelfIap 上方已赋值; obs 是 extern 运行时查询。
    extern BOOL mfObsReceiptVerifierSeen(void);
    extern NSUInteger mfObsFlowClassCount(void);
    BOOL gObsReceipt = mfObsReceiptVerifierSeen();
    NSUInteger gObsFlow = mfObsFlowClassCount();
    BOOL gBlockCodePts = srvTicket || srvSelfIap || gObsReceipt || (gObsFlow > 0);
    if (gBlockCodePts)
        mfLog(@"[f8v2] ★判型总闸: 本地代码点闸门关闭(srvTicket=%d srvSelfIap=%d obs收据=%d obs购买流=%lu) — 框架/sk2/cands 点位不入库",
              srvTicket, srvSelfIap, gObsReceipt, (unsigned long)gObsFlow);
    NSMutableArray *entFuncs = [NSMutableArray array];
    // v2.58.74: 轮次开始 — 标记库中点位"本轮未见", merge 时置 seen, 结束剔除陈旧
    extern void mfAppPatchEntDumpsBeginRound(void);
    extern void mfAppPatchEntDumpsEndRound(void);
    mfAppPatchEntDumpsBeginRound();
    RECON_P("frameworkscan-enter");
    if (!sk2LocalType) {   // v2.58.55: SK2 流型时框架符号点位是噪声, 整块跳过
        uint32_t ic = _dyld_image_count();
        // v2.58.121: 时间预算修正 — v2.58.120 的检查点只在"框架之间"(每16个), 但 dbg_114
        //   实锤 scripting 卡死在单个大框架(ScriptingKit 115MB)的符号遍历里, 永远回不到检查点。
        //   现在: ① 检查改为每框架都做 ② 符号循环内也检查(每 4096 符号一次)。
        CFAbsoluteTime fwT0 = CFAbsoluteTimeGetCurrent();
        unsigned fwScanned = 0, fwTotal = 0;
        // v2.58.172: 外层上限 24→400(与单框架 400 一致) — 旧 24 会在收集阶段过早停下一个框架,
        //   与"收集全部候选后 topN"矛盾。真正的量控在 merge 前排序取 topN, 不在扫描阶段截断。
        for (uint32_t i = 0; i < ic && entFuncs.count < 400; i++) {
            const char *n = _dyld_get_image_name(i);
            if (!n) continue;
            NSString *full = [NSString stringWithUTF8String:n];
            // 只扫 app 自带框架(Containers/Bundle 路径), 排除系统库噪音
            if (![full containsString:@".app/Frameworks/"]) continue;
            fwTotal++;
            fwScanned++;
            if (CFAbsoluteTimeGetCurrent() - fwT0 > 5.0) {
                mfLog(@"[reconP] frameworkscan 时间预算到(5s): 已扫 %u/%u 框架, 收 %lu 点位",
                      fwScanned, fwTotal, (unsigned long)entFuncs.count);
                break;
            }
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
            // v2.58.171: strtab 预筛词表对齐语义打分强锚/权益词(框架级快速门 —
            //   strtab 不含任一权益语义词 → 整框架跳过, 不做符号循环)。与 mfEntSemScore 同源,
            //   避免"预筛放行但符号循环全被语义分淘汰"的空转, 或"预筛太窄漏掉真门框架"。
            static NSArray *kEntPats; static dispatch_once_t o;
            dispatch_once(&o, ^{ kEntPats = @[@"AccessGuard", @"Entitlement", @"entitle",
                                              @"hasValid", @"hasPro", @"Premium", @"premium",
                                              @"Unlock", @"unlock", @"Subscri", @"subscri",
                                              @"Purchas", @"purchas", @"AuthActive", @"canManage",
                                              @"isVip", @"isVIP", @"Membership", @"isPaid", @"Lifetime"]; });
            // v2.58.121: strtab 预筛 — dbg_114 定谳: ScriptingKit nsyms=120 万,
            //   逐符号 strlen+strcmp 要数秒~数十秒(卡死真凶)。改为先在 strtab 里
            //   一次 memmem 找关键字(120 万符号的 strtab 42MB, memmem 毫秒级);
            //   找不到 → 整个框架跳过, 不做符号循环。
            {
                uint32_t strsize2 = 0;
                {
                    const struct load_command *lc2 = (const struct load_command *)((const uint8_t *)h + sizeof(struct mach_header_64));
                    for (uint32_t c2 = 0; c2 < h->ncmds; c2++, lc2 = (const struct load_command *)((const uint8_t *)lc2 + lc2->cmdsize))
                        if (lc2->cmd == LC_SYMTAB) { strsize2 = ((const struct symtab_command *)lc2)->strsize; break; }
                }
                BOOL anyHit = NO;
                if (strsize2 && (strsize2 < 256u*1024*1024)) {
                    for (NSString *pat in kEntPats)
                        if (mfRecFind((const uint8_t *)strtab, strsize2, pat.UTF8String)) { anyHit = YES; break; }
                } else anyHit = YES;   // strsize 异常 → 保守走全扫
                if (!anyHit) continue;
            }
            unsigned imgHits = 0;
            // v2.58.172: 去 12 上限(dbg_159 定谳) — 旧 imgHits<12 = 扫到"符号表前 12 个命中"就停,
            //   ScriptingKit 120 万符号线性遍历, score 10 真门(ProAccessGuard)排在 isEligible/
            //   isAuthorized/checkIsCheater 之后 → 被切掉, 159 全 score 3/5 无真门。
            //   现在: 扫到时间预算(5s)为止, 收集全部 score>0 候选(上限 400 防爆), merge 前按 score
            //   降序取 topN → 真门一定冒头排第一, 陷阱靠负向词(-1)剔除, 数量仍可控(非放洪水进 patch)。
            for (uint32_t k = 0; k < nsyms && imgHits < 400; k++) {
                // v2.58.121: 符号循环内也查预算 — 单框架符号数可能 10 万+(ScriptingKit 120 万),
                //   只在框架间查不够(dbg_114: 8s 预算没生效, 卡死在单框架遍历里)。
                if ((k & 0xFFF) == 0xFFF && (CFAbsoluteTimeGetCurrent() - fwT0 > 5.0)) {
                    mfLog(@"[reconP] frameworkscan 时间预算到(5s, 符号级): 框架 %@ k=%u/%u, 收 %lu 点位",
                          full.lastPathComponent, k, nsyms, (unsigned long)entFuncs.count);
                    break;
                }
                if (!(syms[k].n_type & N_SECT) || !syms[k].n_value) continue;
                const char *nm = strtab + syms[k].n_un.n_strx;
                if (!nm || !(nm[0] == '_' && nm[1] == '$')) continue;   // Swift mangled only
                // v2.57.1 正向过滤(只收真判定函数): Sb(Bool)返回 + tF(函数)/vg(getter)结尾。
                size_t nl = strlen(nm);
                if (nl < 8) continue;
                BOOL endF = !strcmp(nm + nl - 2, "tF");
                BOOL endG = !strcmp(nm + nl - 2, "vg");
                if (!endF && !endG) continue;          // thunk(TQ0_/TA/yyYacfU)/async(tYaF)/metadata 全排除
                if (!strstr(nm, "Sb")) continue;        // 非 Bool 返回不打
                if (endF && strstr(nm, "ySb")) continue;   // v2.57.1: void 返回多参函数含"Sb"字样但非返回值
                // ═══ v2.58.171 识别层: 模块归属过滤 + 语义打分(替代 kEntPats strstr 白名单) ═══
                // ① 模块归属: mangled module 必须 == 框架 leaf 名 → 结构性杀 vendored 第三方库噪声
                //    (Tokenizers/NIOPosix/GRDB 模块名≠框架名, dbg_158 那 5 个垃圾在此被挡, 零词表)。
                char mod[64];
                if (!mfMangledModule(nm, mod, sizeof(mod))) continue;
                char fwLeaf[128];
                {
                    NSString *leaf = full.lastPathComponent ?: @"";   // 如 "ScriptingKit"
                    const char *lc = leaf.UTF8String ?: "";
                    size_t z = 0; for (; lc[z] && z < sizeof(fwLeaf)-1; z++) fwLeaf[z] = (char)tolower((unsigned char)lc[z]);
                    fwLeaf[z] = 0;
                }
                if (strcmp(mod, fwLeaf) != 0) continue;   // 只收框架自有模块的符号(非 vendored 库)
                // ② 语义打分: score>0 才是候选(无语义词的 isSelected/isReady/passwordValid → 0 淘汰)
                char low[256];
                { size_t z = 0; for (; nm[z] && z < sizeof(low)-1; z++) low[z] = (char)tolower((unsigned char)nm[z]); low[z] = 0; }
                int semScore = mfEntSemScore(low);
                if (semScore <= 0) continue;
                {
                        // 同名符号 local/global 双 nlist 去重
                        BOOL dupSym = NO;
                        for (NSDictionary *e in entFuncs)
                            if ([e[@"img"] isEqualToString:full.lastPathComponent] && [e[@"sym"] isEqualToString:[NSString stringWithUTF8String:nm]]) { dupSym = YES; break; }
                        if (dupSym) continue;
                        [entFuncs addObject:@{
                            @"img": full.lastPathComponent,
                            @"sym": [NSString stringWithUTF8String:nm],
                            @"vmaddr": @((unsigned long)syms[k].n_value),
                            @"slide": @((long)slide),
                            @"score": @(semScore),   // v2.58.171: 语义分, 详情页/入库按此降序
                        }];
                        imgHits++;
                        mfLog(@"[f8v2] ★框架门 %s score=%d (mod=%s)", nm, semScore, mod);
                }
            }
        }
        // v2.58 接线: 侦查→实验模拟页数据通道 — 扫到的点位直接合并进 mfEntDumps_<bid>
        // v2.58.171/172: 框架门按语义分降序 — 真门(score 10+, ProAccessGuard 族)靠前, 判定语义(3)垫后。
        if (entFuncs.count > 1)
            [entFuncs sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                int sa = [a[@"score"] intValue], sb = [b[@"score"] intValue];
                return sa > sb ? NSOrderedAscending : (sa < sb ? NSOrderedDescending : NSOrderedSame);
            }];
        // v2.58.172: 排序后取 topN(≤12)入库 — 收集阶段放开(扫全部 score>0), 量控在此。
        //   真门(score 高)一定在前 N 内, 低分噪声被截断。dbg_159: 试用/反作弊已被负向词(-1)剔,
        //   这里再截断保证判定点列表干净可读(用户不必在几十个里翻)。
        {
            const NSUInteger kEntTopN = 12;
            if (entFuncs.count > kEntTopN) {
                NSUInteger dropped = entFuncs.count - kEntTopN;
                [entFuncs removeObjectsInRange:NSMakeRange(kEntTopN, dropped)];
                mfLog(@"[f8v2] 框架门 topN 截断: 保留前 %lu(按 score 降序), 丢弃低分 %lu", (unsigned long)kEntTopN, (unsigned long)dropped);
            }
        }
        // v2.58.169: 判型总闸 — 本地代码点闸门关闭时(服务端型/收据验证型)不入库框架符号点
        if (entFuncs.count && !gBlockCodePts) {
            extern void mfAppPatchEntDumpsMerge(NSArray *);
            mfAppPatchEntDumpsMerge(entFuncs);
        } else if (entFuncs.count && gBlockCodePts) {
            [lines addObject:[NSString stringWithFormat:@"框架符号候选 %lu 个: 判型总闸拦下(本地 patch 对此型无效) — 不入库", (unsigned long)entFuncs.count]];
        }
        }   // v2.58.55: if (!sk2LocalType) 闭合 — SK2 流型时整块框架扫描跳过
        RECON_P("frameworkscan-done");
        if (entFuncs.count && !gBlockCodePts) {
            RECON_P("branch-entfuncs");
            [lines addObject:[NSString stringWithFormat:@"entitlement 判定点位: %lu 个(可 patch) — 见实验模拟页", (unsigned long)entFuncs.count]];
            for (NSDictionary *f in [entFuncs subarrayWithRange:NSMakeRange(0, MIN(4, entFuncs.count))]) {
                NSString *s = f[@"sym"] ?: @"";
                NSString *tail = s.length > 46 ? [s substringFromIndex:s.length - 46] : s;
                [lines addObject:[NSString stringWithFormat:@"  %@:%#lx …%@", f[@"img"], [f[@"vmaddr"] unsignedLongValue], tail]];
            }
        } else {
        // v2.58.21: F9+F8 双路并报 — ServeLog 教训: 旧逻辑"F9 命中即跳过 F8"误判
        // (文案/URL 词表误命中 → 把纯 SK2 代码判定型 app 掐死在 F8 门外)。现在
        // 状态型线索与代码扫描并存, recon 只报数据, 用户在 UI 里自己选主路线。
            // v2.58.20: F9 状态型判定 — 判定数据源形态先行, UserDefaults 型直写
            //   v2.58.35: 侦查=唯一采集器(用户架构定案) — key 列表由 recon 采集打包进
            //   recon dict(stateKeys), F9 卡片只读缓存, 不再独立扫(此前 F9 自己又扫一遍
            //   __cstring+plist, 与侦查卡各扫各的, 定性互相矛盾)。
            extern NSArray *mfStateProbeKeys(void);            // MFStateUnlock.m(F9 状态型判定)
            extern void mfStateReconCacheSet(NSArray *);       // v2.58.35: 侦查=唯一采集器
            RECON_P("stateprobe-enter");
            stateKeys = mfStateProbeKeys();          // 采集(函数级变量, 局部接住教训仍守: 不在参数位内联)
            RECON_P("stateprobe-done");
            mfStateReconCacheSet(stateKeys);                  // F9 卡片吃缓存, 不再独立扫
            // v2.58.35: 状态型判定升级 — 仅静态命中(全是 __cstring 里的死串)不算状态型:
            //   76 key 全静态(i18n 文案 key/类名/埋点 key 过词表门), 判"状态型"
            //   与第一行 RC 云验证自相矛盾。实存 key(app 自己写过/读过的)才是 app 真在
            //   用的状态位。静态候选只作 F9 的"可试探"展示, 不再撑判定。
            NSUInteger liveKeys = 0;
            for (NSDictionary *d in stateKeys) if ([d[@"live"] boolValue]) liveKeys++;
            if (liveKeys > 0) {
                [lines addObject:[NSString stringWithFormat:@"判定数据源: 🔓 状态型(UserDefaults 实存 %lu 语义key, 静态候选 %lu) — 🧪实验模拟→F9 状态解锁 直写",
                    (unsigned long)liveKeys, (unsigned long)stateKeys.count]];
                for (NSDictionary *d in [stateKeys subarrayWithRange:NSMakeRange(0, MIN(3, stateKeys.count))]) {
                    [lines addObject:[NSString stringWithFormat:@"  %@%@ %@",
                        d[@"key"], [d[@"isDate"] boolValue] ? @" 📅" : @"",
                        [d[@"live"] boolValue] ? @"(实存)" : @"(静态)"]];
                }
            } else if (stateKeys.count) {
                [lines addObject:[NSString stringWithFormat:@"判定数据源: 非状态型(静态候选 %lu 全是二进制死串, 无实存 key) — i18n 文案/类名误命中已排除", (unsigned long)stateKeys.count]];
            }
            RECON_P("stateprobe-branch-done");
            // v2.58.9 F8v2: strip 主二进制兜底 — 符号表无判定函数时走 chained fixups 链
            // (imports→SK 词表→bind→GOT slot→stubs→bl 调用点→prologue 归属), 点位合成 @0x 名
            // v2.58.21: 不再被 F9 else 掐死 — 双路并报(状态型与代码型可并存)
            // v2.58.36: 云验证型降权 — 实测: RC 云验证型 app 12 个 F8v2
            //   swifttext 点位⚡后购买页崩(ips: String.init(localized:) @Observable 渲染,
            //   被patch函数返回对象非Bool, mov w0,#1 → 调用方当指针解 → SIGSEGV)。
            //   云SDK在场 = 判定本体在云端回包, F8 点位对这类 app 无意义还高危 —
            //   不入库不显示, lines 明说路线是 mock。纯 StoreKit/SK1 型 app 照旧入库。
            {
            // v2.58.55: f8v2/sk2pts/sk2LocalType 已提升到函数前部(框架块之前) —
            //   这里只消费, 不再重复调用/重复判型
            NSArray *candsRef = cands;
            RECON_P("merge-enter");
            NSArray *sk2ptsRef = sk2pts;
            extern void mfAppPatchEntDumpsMerge(NSArray *);
            NSArray *mergePts = sk2ptsRef;
            RECON_P("merge-predone");
            if (gBlockCodePts) {
                // v2.58.169 判型总闸: 服务端型/收据验证型 → sk2 代码点结构性无效, 一律不入库
                if (mergePts.count)
                    [lines addObject:[NSString stringWithFormat:@"代码判定点 %lu 个: 判型总闸拦下(本地 patch 对此型无效) — 不入库", (unsigned long)mergePts.count]];
            } else if (cloudBrands.count) {
                // v2.58.173 云型 sk2 代码点抑制: reflix 战役定谳 — 云验证型双因子 =
                //   mock(云端回包) + F10 深槽装载点(判定点腿, reflix 的 0x14211bc)。
                //   sk2vfy/sk2br/sk2plan 是标准 SK2 API 通用结构(2.58.116 定谳: 任何 SK2
                //   app 都有, 非特征), 判定本体在云端 → 入库只会用通用噪声淹没真判定点腿。
                //   → sk2 点不入库(只 mfLog 记录, 不进详情页 lines); F10 深槽由下方专管。
                if (mergePts.count)
                    mfLog(@"[f8v2] 云验证型 sk2 代码点 %lu 个不入库(通用 SK2 结构非判定腿, 判定点腿=F10 深槽)", (unsigned long)mergePts.count);
            } else if ([mergePts isKindOfClass:[NSArray class]] && mergePts.count) {
                mfAppPatchEntDumpsMerge(mergePts);
                RECON_P("merge-done");
                [entFuncs addObjectsFromArray:mergePts];
                // v2.58.117: 分真门/候选播报 — 不再用一个虚高总数误导(dbg_108 用户反馈)
                NSUInteger nRG = 0;
                for (NSDictionary *f in mergePts)
                    if ([f[@"shape"] isEqualToString:@"sk2vfy"] && [f[@"score"] intValue] >= 99) nRG++;
                if (nRG > 0)
                    [lines addObject:[NSString stringWithFormat:@"代码判定点: %lu 个已入库(★真门 %lu · 其余候选 %lu) — 见实验模拟页",
                                      (unsigned long)mergePts.count, (unsigned long)nRG,
                                      (unsigned long)(mergePts.count > nRG ? mergePts.count - nRG : 0)]];
                else
                    [lines addObject:[NSString stringWithFormat:@"代码判定点: %lu 个已入库(isPro 写点/读侧 getter, 指令级 mov #1) — 见实验模拟页", (unsigned long)mergePts.count]];
            }
            // v2.58.55: SK2 流型(非云)抑制 F8v2 swifttext 点位 — dbg_58 用户拍板:
            //   "侦查详情页都给出那么详细的判决了, 为什么还要把不相干的点位传到实验
            //   模拟页?" — 判型已定 SK2 流型时, F8 getter 点位是噪声不入库; 云型 F10
            //   deepslot 仍保留(双因子实测)。
            if (sk2LocalType) {
                // 抑制 F8 点位: 不 merge 不显示 — lines 只报 SK2 路线
                [lines addObject:@"F8v2 swifttext 候选: 该 app 已有 isPro 指令级点位, 函数符号候选未入库"];
            } else if (cloudBrands.count) {
                // v2.58.40: F10 点位也要 merge 入库(云验证型专属判定点 — 深槽装载链)
                NSUInteger nDeep = 0;
                if ([cands isKindOfClass:[NSArray class]]) {
                    NSMutableArray *deepOnly = [NSMutableArray array];
                    for (NSDictionary *c in cands) if ([c[@"shape"] isEqualToString:@"deepslot"]) { [deepOnly addObject:c]; nDeep++; }
                    if (deepOnly.count) {
                        extern void mfAppPatchEntDumpsMerge(NSArray *);
                        mfAppPatchEntDumpsMerge(deepOnly);
                        [entFuncs addObjectsFromArray:deepOnly];
                    }
                }
                if (nDeep) {
                    [lines addObject:[NSString stringWithFormat:@"entitlement 判定点位: %lu 个 F10 深槽装载点已入库 — 见实验模拟页 ⚡", (unsigned long)nDeep]];
                    [lines addObject:@"解锁路线: 云端 mock(订阅注入开关) + ⚡深槽装载点 双因子 — F8v2 swifttext 点位对云验证型高危, 已抑制不入库"];
                } else {
                    [lines addObject:[NSString stringWithFormat:@"entitlement 判定点位: F10 未命中(无深槽装载链) — F8v2 swifttext %lu 候选对云验证型高危, 均不入库", (unsigned long)([cands isKindOfClass:[NSArray class]] ? cands.count : 0)]];
                    [lines addObject:@"解锁路线: 云端 mock(订阅注入开关)单因子 — 深槽链不在本 app 判型内"];
                }
            } else if ([candsRef isKindOfClass:[NSArray class]] && candsRef.count && !gBlockCodePts) {
                extern void mfAppPatchEntDumpsMerge(NSArray *);
                mfAppPatchEntDumpsMerge(candsRef);
                [entFuncs addObjectsFromArray:candsRef];
                // v2.58.76: 标签按 score 来源分开报 — 旧实现一律写"F8v2 fixups 链", 实际
                //   库里多半是 f8v3(score 91~93)共享 bool getter, 把排查方向带偏(dbg_78)。
                NSUInteger nSem = 0, nGetter = 0;
                for (NSDictionary *f in candsRef)
                    if ([f[@"score"] intValue] >= 91 || [f[@"shape"] length]) nGetter++; else nSem++;
                [lines addObject:[NSString stringWithFormat:@"entitlement 判定点位: %lu 个(语义锚定 %lu · getter %lu)", (unsigned long)candsRef.count, (unsigned long)nSem, (unsigned long)nGetter]];
                for (NSDictionary *f in [candsRef subarrayWithRange:NSMakeRange(0, MIN(6, candsRef.count))]) {
                    NSString *src = ([f[@"score"] intValue] >= 91 || [f[@"shape"] length]) ? @"getter" : @"语义锚定";
                    [lines addObject:[NSString stringWithFormat:@"  [%@] %@:%@ score=%@", src, f[@"img"], f[@"vmaddr"], f[@"score"] ?: @"?"]];
                }
            } else [lines addObject:@"entitlement 判定点位: 未发现(框架无符号判定函数, 主二进制 fixups 链无 SK 消费候选)"];
            }
        }   // v2.58.121: else 块闭合 — v2.58.55 重排时吞掉了这个 }!
            //   dbg_115 定谳: 括号深度分析显示 if(entFuncs.count){...}else{ 之后
            //   所有代码(stateprobe/merge/verdict/return)都困在 else 里(深度 2)。
            //   entFuncs.count>0(框架扫到点位, scripting 命中)时走 if → 跳过 return →
            //   函数掉出尾部不返回 → recon 为垃圾 → 无 [recon] 行(但后续代码继续执行)。

    RECON_P("branch-done");
    // ---- 判定(动态拼接, 可叠加: 云+mach 双面) ----
    BOOL cloud = cloudBrands.count > 0;
    // v2.58.65: sk2stream 概念废除(sk2ver 判别点=死代码已删) — 留变量仅为 return 兼容
    //   (恒 NO)。判型优先级: 云 > mach > 服务器 > 状态型/代码判定点。
    BOOL sk2stream = sk2LocalType;
    // v2.58.35: 云验证优先级定案(用户架构: 侦查卡是定性器) — RC/Adapty 等云 SDK 在场时
    //   判定本体在云端回包, UserDefaults 状态 key 只是缓存镜像(直写有概率生效但不定死
    //   类型)。verdict 云分支前置, 状态型只作 lines 里的辅助线索(实存 key 才标注)。
    BOOL stateType = NO;
    {
        // 状态型 = 无云无 mach + 实存语义 key 数量 ≥2(静态死串不算, 76 假案定谳)
        // v2.58.50: SK2 流型在场时状态 key 是镜像 — 降级为线索, 不判状态型
        if (!cloud && !mach && !sk2stream) {
            NSUInteger live = 0;
            for (NSDictionary *d in stateKeys) if ([d isKindOfClass:[NSDictionary class]] && [d[@"live"] boolValue]) live++;
            if (live >= 2) stateType = YES;
        }
    }
    // F7 服务器权益型(2026-09-06 mailnow 案定案): 无云 SDK + 纯 SK + WebView 权益标志(FlexCall/loadSuccess
    // /premium/no_ad/vip 类 JS 桥字段) → 权益本体在服务端会话, 本地解锁无意义
    BOOL serverSide = NO;
    RECON_P("verdict-enter");
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
    NSUInteger nCodePts = 0;
    for (NSDictionary *f in sk2pts)
        if ([f[@"shape"] isEqualToString:@"sk2pro"] || [f[@"shape"] isEqualToString:@"sk2get"]
            || [f[@"shape"] isEqualToString:@"sk2br"] || [f[@"shape"] isEqualToString:@"sk2vfy"]
            ) nCodePts++;
    // v2.58.117: 真门计数 — 只算 score>=99 的 sk2vfy(真门形态: Optional tag 解包+retain)。
    //   dbg_108 用户反馈: "代码判定型 65 点"里绝大多数是通用噪声, 数字虚高误导。
    NSUInteger nRealGate = 0;
    for (NSDictionary *f in sk2pts)
        if ([f[@"shape"] isEqualToString:@"sk2vfy"] && [f[@"score"] intValue] >= 99) nRealGate++;
    // v2.58.168/169 B: 观测喂判型 — 信号已在判型总闸(上方)取过, 这里复用 gObsReceipt/gObsFlow。
    BOOL obsReceipt = gObsReceipt;
    NSUInteger obsFlow = gObsFlow;
    // v2.58.173: F10 深槽判定点腿入库数(reflix 双因子第二条腿 — "判定点腿飞了"根因修复)。
    //   云型 sk2 已在上方抑制, entFuncs 云型只余 deepslot; 此处专数 deepslot 保证语义精确。
    NSUInteger nDeepLib = 0;
    for (NSDictionary *f in entFuncs) if ([f[@"shape"] isEqualToString:@"deepslot"]) nDeepLib++;
    NSString *verdict;
    if (cloud && mach)      verdict = [NSString stringWithFormat:@"%@ 云端订阅验证 + 本地许可服务器(异常端口) — 双面, mock+⚡F10 深槽点 双因子", cloudBrands.allObjects.firstObject];
    else if (cloud)         verdict = [NSString stringWithFormat:@"%@ 云端订阅验证 — mock 回包 + ⚡F10 深槽装载点 双因子解锁", cloudBrands.allObjects.firstObject];
    else if (mach)          verdict = @"本地许可服务器(异常端口 MIG, 同族架构)";
    // v2.58.65: "SK2 事务流验证型"判型已废(用户定案: 实机三轮零作用=死代码)
    else if (serverSide)    verdict = @"服务器权益型(SK+WebView 桥权益标志) — 权益在服务端会话, 本地解锁无意义, 跳过";
    // v2.58.75: 服务端权威判定型 — 优先于代码点播报(bplayer 案: 35 个形态点是通用
    //   判空噪声, 全 ⚡ 不亮已实证; 判定链在自家后端, 本地 patch 无意义)
    else if (srvSelfIap)    verdict = @"自研服务端权益型(无本地 SK 权益链, /iap/* 端点下发) — 本地解锁无意义, 跳过";
    // v2.58.124 (dbg_117 定谳): 服务器授权票据型 — target-app 案。
    //   180 点(含权益锚定门 + 双守卫组)全 patch 落地但 UI 不亮, 二进制深挖定谳:
    //   权益 = 服务器签发 JWT 票据(iat/exp/kid/grace_seconds) + 本地验票,
    //   本地 StoreKit 结果只作上报输入。本地 patch 结构性无效 — 明确播报避免用户白试。
    else if (srvTicket)     verdict = @"服务器授权票据型(JWT 票据 + entitlements:sync, permanent_entitlements_authoritative) — 权益在服务端, 本地 patch 无效, 跳过";
    // v2.58.116: sk2vfy(本地 SK2 验证判定门)在场时的判型播报 — 与 srvSelfIap 互斥
    //   (srvSelfIap 要求无本地链; 此处专指有本地链且扫出验证门的情形)。
    //   抓包实证(dbg_108): 解锁后 /iap/pro-status 仍返回 {"active":false} →
    //   端点仅遥测, 权益 100% 本地判定 → 解锁路径 = sk2vfy 门 patch。
    // v2.58.65: 指令级代码判定点优先播报 — dbg_68 用户定案: 真正解锁的是
    //   sk2pro(写点)+sk2get(读侧) 这类**指令级 patch**, UserDefaults 直写只是辅助/部分。
    // v2.58.117: 文案跟上 — 用户反馈(dbg_108) "65 点"虚高(含通用噪声/标准 SK2 门)。
    //   现在: 有真门时优先播报真门数(score>=99), 其余点标注为"候选"; 无真门时旧文案保留。
    else if (nRealGate > 0) verdict = [NSString stringWithFormat:@"代码判定型(本地 SK2 验证链) — ★真门 %lu 个(Optional 解包门, 优先试) · 其余 %lu 候选 — 实验模拟页⚡即解锁",
                                       (unsigned long)nRealGate, (unsigned long)(nCodePts > nRealGate ? nCodePts - nRealGate : 0)];
    else if (nCodePts > 0)  verdict = [NSString stringWithFormat:@"代码判定型(指令级 patch %lu 点: isPro 写点/读侧 getter) — 实验模拟页⚡即解锁", (unsigned long)nCodePts];
    else if (stateType)     verdict = @"状态型(UserDefaults 实存语义key) — 🧪实验模拟→F9 状态解锁 直写";
    // v2.58.168 B: 观测确证的收据验证型 — 运行时铁证优先于静态兜底(解决"判定点未发现")。
    //   条件: 观测命中收据验证类 或 观测挂到 SK1 购买流消费者(paymentQueue:updatedTransactions:)。
    else if (obsReceipt || obsFlow > 0) verdict = [NSString stringWithFormat:@"收据验证型(运行时观测确证: %@购买流消费者 %lu 个) — 解锁路线: 🧪实验模拟页 L1 收据伪造开关(判定读收据, 非代码门)",
                                       obsReceipt ? @"收据验证类命中 · " : @"", (unsigned long)obsFlow];
    // v2.58.7: 纯 StoreKit 本地校验型分支(2.58.6 缺失 — SK2 明明已判定却显示"未发现订阅验证 SDK"兜底文案)
    else if (skLocal)       verdict = [NSString stringWithFormat:@"纯 StoreKit 本地校验型(%@ · %@) — 判定点已入库, 实验模拟页左划 patch", skType, validator];
    else                    verdict = @"未发现订阅验证 SDK";
    if (cloudBrands.count > 1) {
        NSString *names = [[cloudBrands.allObjects sortedArrayUsingSelector:@selector(compare)] componentsJoinedByString:@"/"];
        verdict = [verdict stringByReplacingOccurrencesOfString:cloudBrands.allObjects.firstObject
                                                     withString:[NSString stringWithFormat:@"%@(疑似多 SDK)", names]];
    }

    // ══════════ v2.58.170 判型总闸第二刀: 单一 type + 单一 route 收口 ══════════
    // 病(dbg_155/156): 详情页 42 处 addObject 各 detector 自说自话 → 同页出现
    //   "服务器票据型本地无效" vs "解锁路线云端mock" vs "F10均不入库" 三句打架 + 一堆
    //   内部过程日志(N个拦下/未命中)。用户: 这是判型总结页, 不是日志垃圾场。
    // 治: 判型信号已全就绪(上方), 这里一次性定 type(唯一) + route(唯一解锁路线)。
    //   详情页只显示 verdict(结论) + route(该怎么做), 过程日志降级(见下 mfReconShowDetailPage 过滤)。
    NSString *mfType, *route;
    if (cloud && mach)      { mfType = @"云验证+本地许可服务器"; route = nDeepLib > 0
                                ? [NSString stringWithFormat:@"实验模拟页双因子: ①订阅注入(mock 回包) ②⚡F10 深槽判定点 %lu 个 ③EXCPROBE 应答器", (unsigned long)nDeepLib]
                                : @"实验模拟页: 订阅注入(mock 回包) + EXCPROBE 应答器"; }
    else if (cloud)         { mfType = nDeepLib > 0 ? @"云端订阅验证型(双因子: mock + F10 深槽判定点)" : @"云端订阅验证型";
                              route = nDeepLib > 0
                                ? [NSString stringWithFormat:@"实验模拟页双因子: ①订阅注入开关(mock 回包) ②判定点列表⚡F10 深槽装载点 %lu 个", (unsigned long)nDeepLib]
                                : @"实验模拟页: 订阅注入开关(mock 回包)"; }
    else if (mach)          { mfType = @"本地许可服务器型"; route = @"实验模拟页: 开 EXCPROBE 应答器"; }
    else if (serverSide)    { mfType = @"服务器权益型"; route = @"⛔ 权益在服务端会话, 本地解锁无效 — 无可用本地路线"; }
    else if (srvSelfIap)    { mfType = @"自研服务端权益型"; route = @"⛔ 权益由自家后端下发, 本地解锁无效 — 无可用本地路线"; }
    else if (srvTicket)     { mfType = @"服务器授权票据型"; route = @"⛔ 权益=服务器签发 JWT 票据, 本地 patch 结构性无效 — 无可用本地路线"; }
    else if (obsReceipt || obsFlow > 0) { mfType = @"收据验证型(运行时观测确证)"; route = @"实验模拟页: L1 收据伪造开关"; }
    else if (nRealGate > 0) { mfType = @"代码判定型(本地 SK2 验证链)"; route = [NSString stringWithFormat:@"实验模拟页判定点列表 ⚡ patch(★真门 %lu 个优先)", (unsigned long)nRealGate]; }
    else if (nCodePts > 0)  { mfType = @"代码判定型(指令级 patch)"; route = [NSString stringWithFormat:@"实验模拟页判定点列表 ⚡ patch(%lu 点)", (unsigned long)nCodePts]; }
    else if (stateType)     { mfType = @"状态型(UserDefaults)"; route = @"实验模拟页: F9 状态解锁直写"; }
    else if (skLocal)       { mfType = [NSString stringWithFormat:@"纯 StoreKit 本地校验型(%@)", skType]; route = @"实验模拟页判定点列表 ⚡ patch"; }
    else                    { mfType = @"未识别"; route = @"未发现订阅验证 SDK — 可开实时日志观测 + 逛购买页重扫"; }

    // v2.58.55: 本次会话侦查点位缓存 — 已废除(2.58.61 用户定案)
    //   侦查→mfAppPatchEntDumpsMerge 入库, 实验/列表 UI 只读持久层, 无"本次有效"概念
    // v2.58.74: 轮次结束 — 剔除本轮未扫出且用户未持久化的陈旧点后, 卡片"共 N 点"= 本轮真值
    mfAppPatchEntDumpsEndRound();
    RECON_P("done");
    // v2.58.170 第二刀: 详情页只留"判型证据"类 lines(SK形态/SDK指纹/端点), 过程日志(N个拦下/
    //   未命中/已入库/深槽点)剔除 —— 结论页只讲结论, 过程去 [f8v2]/[recon] 调试行。
    NSMutableArray *cleanLines = [NSMutableArray array];
    for (NSString *l in lines) {
        if ([l containsString:@"拦下"] || [l containsString:@"未命中"] || [l containsString:@"均不入库"]
            || [l containsString:@"已入库"] || [l containsString:@"候选未入库"] || [l containsString:@"深槽装载点"]
            || [l containsString:@"判定点位:"] || [l containsString:@"解锁路线:"]) continue;   // 过程/旧路线文案 → 详情页不显示(route 统一收口)
        [cleanLines addObject:l];
    }
    return @{@"verdict": verdict, @"type": mfType, @"route": route, @"lines": cleanLines,
             @"cloud": @(cloud), @"mach": @(mach), @"srv": @(serverSide), @"sk": @(skLocal),
             @"sk2": @(sk2stream),
             @"sktype": skType, @"validator": validator,
             @"entFuncs": entFuncs,
             @"stateKeys": stateKeys};   // v2.58.35: 侦查=唯一采集器 — F9 卡片吃这个, 不独立扫
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
    // v2.58.170 第二刀: 详情页头 = 判型结论(type) + 解锁路线(route), 单一收口。
    UILabel *v = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 32, 44)];
    v.text = [NSString stringWithFormat:@"判型: %@", recon[@"type"] ?: recon[@"verdict"]];
    v.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    v.numberOfLines = 0;
    v.textColor = [recon[@"cloud"] boolValue] ? [UIColor systemGreenColor] :
                  [recon[@"mach"] boolValue] ? [UIColor systemPurpleColor] :
                  [recon[@"sk"] boolValue] ? [UIColor systemBlueColor] : [UIColor labelColor];
    [v sizeToFit];
    CGRect vf = v.frame; vf.origin = CGPointMake(16, 46); vf.size.width = g_mfCardW - 32; v.frame = vf;
    [page addSubview:v];
    // 解锁路线行(唯一, 绿=有路线 / 灰=服务端型无本地路线)
    CGFloat routeY = CGRectGetMaxY(v.frame) + 6;
    UILabel *rl = [[UILabel alloc] initWithFrame:CGRectMake(16, routeY, g_mfCardW - 32, 40)];
    NSString *routeTxt = recon[@"route"] ?: @"";
    rl.text = [NSString stringWithFormat:@"路线: %@", routeTxt];
    rl.font = [UIFont systemFontOfSize:12.5];
    rl.numberOfLines = 0;
    rl.textColor = [routeTxt hasPrefix:@"⛔"] ? [UIColor systemGrayColor] : [UIColor systemTealColor];
    [rl sizeToFit];
    CGRect rf = rl.frame; rf.origin = CGPointMake(16, routeY); rf.size.width = g_mfCardW - 32; rl.frame = rf;
    [page addSubview:rl];

    CGFloat tvY = 96;
    NSArray *entFuncs = recon[@"entFuncs"];
    CGFloat btnY = CGRectGetMaxY(rl.frame) + 10;   // v2.58.170: 接在 type+route 行之后(不再硬编码 92, 防与新头部重叠)
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
        // v2.54.0: mach 型(本地许可服务器, 同族) → 引导去开 EXCPROBE 应答器
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
