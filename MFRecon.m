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
// ServeLog 驼峰串(Entitle/Subscription)全 miss 的 mf_debug_25 定谳修复
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
// yimuliaoran 实战(mf_debug_11)暴露三个新问题:
//   ① dlsym 解析面不全: Product 系符号能解析, Transaction 系 miss →
//      扫到的全是 Product 显示层函数(证据行 score 全 0), 判定函数漏网
//   ② nCall 128 截断: 大 app SK 调用点超限, 排位靠后的判定函数被砍
//   ③ patch 后重扫污染: 已 patch 函数头(mov w0,#1;ret)不再是 prologue,
//      回溯越过真头落到前一函数体内 → 两次会话点位漂移 ~0x1A0
// rev3(2.58.12 后): rev2 的 dladdr 分类法在 iOS17+ 全灭(mf_debug_13 stub-match
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
    #define F8V2_BAIL(tag) do { mfLog(@"[f8v2] ✗ 步骤:%s 中断", tag); return nil; } while (0)

    // ---- LC: __text/__stubs section(rev2 不再需要 fixups 表) ----
    const struct load_command *lc = (const struct load_command *)((const uint8_t *)mh + sizeof(struct mach_header_64));
    uint64_t textVM = 0, textSize = 0, stubVM = 0, stubSize = 0, textFileOff = 0;
    uint64_t baseVM = 0;   // v2.58.52: __TEXT vmaddr(sk2pro 串定位)
    uint64_t constSecVM[8] = {0}; uint64_t constSecSize[8] = {0}; int nConstSec = 0;
    // v2.58.79: __cstring section — SKU 串扫描用(mf_debug_81 定谳: 旧实现扫 __text
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
    // mf_debug_12 stub-probe bail 实锤); 3/32 合法即定步进, 全失败回退 12B
    // (分类循环有 adrp+ldr 形态过滤, 错位项自然跳过, 只损失覆盖率不误报)
    uint64_t stubStep = 0;
    for (uint64_t st = 12; st <= 16; st += 4) {
        int wellFormed = 0, checked = 0;
        for (uint64_t off = 0; off + 12 <= stubSize && checked < 32; off += st) {
            uintptr_t a = (uintptr_t)stubVM + (uintptr_t)slide + off;
            uint32_t i1 = *(const uint32_t *)a, i2 = *(const uint32_t *)(a + 4), i3 = *(const uint32_t *)(a + 8);
            checked++;
            // adrp 完整判定 = (ins & 0x9F000000)==0x90000000 — 0x90/0xb0/0xd0 开头都是 adrp(immlo 在低2位);
            // v2.58.11 只查 >>26==0x24 漏掉 immlo≠0 形态 → yimuliaoran 前7个stub全BAD → stub-probe bail(mf_debug_12 实锤)
            if ((i1 & 0x9F000000) == 0x90000000 && (i2 & 0xFFC00000) == 0xF9400000 && (i3 & 0xFFFFFC1F) == 0xD61F0000) wellFormed++;
        }
        if (wellFormed >= 3) { stubStep = st; break; }
    }
    if (!stubStep) stubStep = 12;   // 探测失败不 bail — 回退常规, 分类循环自滤错位项
    mfLog(@"[f8v2] stub区=%lluB 步进=%llu", (unsigned long long)stubSize, (unsigned long long)stubStep);

    // ---- stub 分类 rev3: bind 链直读(零符号查询, 纯 LINKEDIT 元数据) ----
    // dyld 源码定谳: dladdr 走 findClosestSymbol(需 local symtab) — iOS17+ cache
    // local symbols 在独立 .symbols 文件运行时不可用 → dli_sname 全 null 全灭(mf_debug_13
    // stub-match 实锤)。dlsym 走 export trie 可用, 但只给一个地址不认 stub。
    // rev3 = 回 2.58.9 的 bind 链路线: dyld 只改写 GOT slot 的**值**, LINKEDIT 里
    // 的链描述(page_starts/next/ordinal)原样保留 — 静态 Python 版 596/596 全解同款算法
    struct { uint64_t vmaddr, vmsize, fileoff, filesize; const uint8_t *mem; } segs[8];
    int nSegs = 0;
    lc = (const struct load_command *)((const uint8_t *)mh + sizeof(struct mach_header_64));   // 重置! 上个循环已走到底(mf_debug_14 fixblob-locate 实锤)
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
    for (uint32_t si = 0; si < segCount && nSlot < F8V2_MAXSLOT; si++) {
        uint32_t segInfoOff = *(const uint32_t *)(fixBase + startsOff + 4 + si * 4);
        if (!segInfoOff) continue;                              // 该段无 fixups
        const uint8_t *sgB = fixBase + startsOff + segInfoOff;
        // dyld_chained_starts_in_segment: size u32@0, page_size u16@4, format u16@6, segment_offset u64@8, max_valid u32@16, page_count u16@20, page_start[]@22
        if ((uintptr_t)sgB + 22 > (uintptr_t)fixBase + fixSize) continue;
        uint16_t pageSize = *(const uint16_t *)(sgB + 4);
        uint16_t pageCount = *(const uint16_t *)(sgB + 20);
        // segment_offset 是相对镜像基址的偏移(0x104000), 不是绝对 vmaddr(mf_debug_15 bind-walk 实锤)
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
        for (uint32_t pi = 0; pi < pageCount && nSlot < F8V2_MAXSLOT; pi++) {
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
            for (int ci2 = 0; ci2 < nCS && nSlot < F8V2_MAXSLOT; ci2++) {
                uint32_t cur = chainStarts[ci2]; int guard = 0;
                while (guard++ < 100000 && nSlot < F8V2_MAXSLOT) {
                    uint64_t fo = segFO + (uint64_t)pi * pageSize + cur;
                    if (fo + 8 > binLen) break;                  // 越界(段截断/紧凑布局)
                    uint64_t q = *(const uint64_t *)(bd + fo);    // 磁盘链 qword — bind 元数据原样
                    if (q >> 63) {                               // bind entry
                        uint32_t ord = (uint32_t)(q & 0xFFFFFF);
                        if (ord < importsCount) { slotVM[nSlot] = segVM + (uint64_t)pi * pageSize + cur; slotOrd[nSlot] = ord; nSlot++; }
                    }
                    uint32_t nxt = (uint32_t)((q >> 51) & 0xFFF);
                    if (!nxt) break;
                    cur += nxt * 4;
                }
            }
        }
    }
    mfLog(@"[f8v2] bind链 slot=%d (imports=%u)", nSlot, importsCount);
    if (!nSlot) F8V2_BAIL("bind-walk");

    // ---- stub → slot 匹配 → SK 词表过滤 ----
    // slot 查找 O(nSlot)×596 — nSlot~1600 可接受; skStubNames 直接指向 symPool(静态区, 生命周期 OK)
    uint64_t skStubVM[128]; const char *skStubNames[128]; int nSkStub = 0;
    int nCE = 0, nUpd = 0, nPID = 0;
    for (uint64_t off = 0; off + 12 <= stubSize && nSkStub < 128; off += stubStep) {
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
            if (strstr(cand, "8StoreKit")) nm = cand;
            break;
        }
        if (!nm) continue;
        if (strstr(nm, "currentEntitlements")) nCE++;
        if (strstr(nm, "7updates")) nUpd++;
        if (strstr(nm, "9productID")) nPID++;
        skStubVM[nSkStub] = stubVM + off;
        skStubNames[nSkStub] = nm;
        nSkStub++;
    }
    if (!nSkStub) F8V2_BAIL("stub-match");
    mfLog(@"[f8v2] SK stub=%d (currentEntitlements=%d updates=%d productID=%d)", nSkStub, nCE, nUpd, nPID);
    // v2.58.16: stub 明细日志 — mf_debug_16 实锤运行时 SK stub=22 vs 静态 17, 差 5 个
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
    // sk2pro (v2.58.52): isPro 写入点 — mf_debug_54 定谳: 空流时判别点循环体
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
                                // v2.58.56: 真判定形态(本地静态验证实锤, mf_debug_58 转储):
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
                    //   (旧 movz#0+strb 回溯是旧值形态, 方向错 — mf_debug_60 仍 0 命中, 已废)
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
                //   取决于运行时(未购买态可能不跑, mf_debug_65 sk2diag=nil 实锤)。
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
    // sk2dat (v2.58.71): B 路 — 无锚数据源判定点扫描。
    //   动机: sk2pro 门 = 状态播报串(bplayer 类 app 不打 oslog → 门死),
    //   引擎四路全空但 app 明明是 SK2 流消费者(SK stub=33 实测)。
    //   B 路零字符串依赖: 全 __TEXT 扫数据源装载形态 ldr xT,[xK,#imm]
    //   + cmp xT,#0 + cset wS,ne(存在→真方向)。本地实证(hostlog):
    //   形态A 全 TEXT 仅 4 处, ne 门后剩 1 = 已知真点 0x1000a2f68, 0 误报
    //   (3 处误报全为 cset eq 反向语义)。patch = movz xT,#1(与 sk2pro 同语义)。
    // =====================================================================
    {
        int nDat = 0;
        for (uint64_t off = 0; off + 12 <= textSize; off += 4) {
            uint32_t w1 = *(const uint32_t *)(bd + textFileOff + off);
            if ((w1 & 0xFFC00000) != 0xF9400000) continue;      // ldr xT,[xK,#imm12]
            uint32_t T1 = w1 & 0x1F;
            if (T1 == 31) continue;
            uint32_t w2 = *(const uint32_t *)(bd + textFileOff + off + 4);
            if ((w2 & 0xFFFFFC1F) != 0xF100001F) continue;      // cmp xT,#0
            if (((w2 >> 5) & 0x1F) != T1) continue;
            uint32_t w3 = *(const uint32_t *)(bd + textFileOff + off + 8);
            // cset wS,ne 精确判定: 0x1A9F07E0。
            // v2.58.72 修: 旧掩码 0xFFFF0FFF/0x1A9F07E1 恒假(cset cond 在位15-12,
            //   被掩掉后低半字节又与 0xE1 比) → 设备上 sk2dat 恒 0 命中(mf_debug_74)。
            //   注: CSET 的 cond 字段 = invert(实际cond), 故 ne→字段0(0x1A9F07E0),
            //   eq→字段1(0x1A9F17E0)。掩码 0xFFFFFFE0 已钉死字段=0, 无需二次判断。
            if ((w3 & 0xFFFFFFE0) != 0x1A9F07E0) continue;      // cset w*,#ne 精确
            uint64_t a6 = textVM + off;
            BOOL dup6 = NO;
            for (NSDictionary *sp in sk2pts)
                if ([sp[@"vmaddr"] unsignedLongLongValue] == a6) { dup6 = YES; break; }
            if (dup6) continue;
            uint32_t movNew = 0xD2800000u | (1u << 5) | T1;     // movz xT,#1
            nDat++;
            [sk2pts addObject:@{
                @"img": mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main",
                @"sym": [NSString stringWithFormat:@"sk2dat@%#llx.%u", (unsigned long long)off, T1],
                @"vmaddr": @(a6),
                @"slide": @((long)slide),
                @"score": @(95),
                @"calls": @(0),
                @"shape": @"sk2dat",
                @"kind": @"sk2dat",
                @"old": mfLeHex(w1),
                @"new": mfLeHex(movNew),
            }];
            mfLog(@"[f8v2] ★sk2dat @%#llx (ldr x%u→movz x%u,#1, cset ne — B 路无锚)", (unsigned long long)a6, T1, T1);
        }
        mfLog(@"[f8v2] sk2dat: B 路无锚数据源点=%d 个(cset ne 门, 零字符串依赖)", nDat);
    }

    // =====================================================================
    // sk2br (v2.58.78): 分支粒度判定点 — 打"Pro 门"的分支决策, 不砍函数头。
    //   动机(mf_debug_79): 真点 0x1004a080c/0x100c053ac 函数头 mov w0,#1;ret 全空转 —
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
        // v2.58.79: SKU 串在 __cstring(不是 __text!) — mf_debug_81 定谳:
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


    NSString *imgName = mainPath ? [[NSString stringWithUTF8String:mainPath] lastPathComponent] : @"main";
    NSMutableArray *out = [NSMutableArray array];
    NSUInteger f8v2Seg = 0;   // v2.58.76: F8v2 段边界(语义锚定候选, 截断时必须保位)
    // v2.58.16: top6→top12 + CE 消费者无条件保位 — mf_debug_16 实锤真判定函数
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
    // F8v3 (2026-09-12): 判定层深挖 — mf_debug_17 全候选⚡不亮定谳:
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
                    // v2.58.23: 语义串形态门 — mf_debug_23 实锤 ServeLog UI 文案
                    // ("No active purchase..."含 purchas)混进 S 集 → 显示层 bl 的基础库
                    // helper fan≥2 全中 → 205 accessor 噪声爆炸(真 oracle 1~3 个)。
                    // 引用串(代码里 adrp+add 指到它)是紧凑 camelCase/点分标识符,
                    // 不是带空格/冒号的句子 — 同 F9 stateKeyShapeOK 判据。
                    BOOL shapeBad = NO;
                    if (memchr(s, ' ', sl) || memchr(s, ':', sl) || memchr(s, '/', sl)) shapeBad = YES;
                    // v2.58.26: 词表改小写不敏感匹配(mf_debug_25 定谳: ServeLog 驼峰命名
                    // EntitlementManager/_hasProSubscription 被 strstr 小写词表全 miss,
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
                // v2.58.24: 门槛修正 — mf_debug_24 ServeLog 实锤语义串形态门把纯文案型 app
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
                            // v2.58.19: 不再跳过 W 目标 — mf_debug_19 定谳: 语义函数可
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
                    // ---- 形态分类(mf_debug_18 定谳: mov w0,#1 对指针返回型=炸弹) ----
                    // mf_debug_18: ⚡0x1000a65f0(metadata accessor) → 内购页
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
                        // 形态(mf_debug_25 ServeLog 静态定谳: hasProSubscription getter 尾
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
                        // v2.58.23: 门控重立 — mf_debug_23 ServeLog 205 accessor 定谳:
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
                            // v2.58.47: 共享 bool 加 fan≤64 门 — mf_debug_49(HostLog)实锤
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
                    // 使 getter 0 个 bl 调用者, fan 模型结构性失明 — mf_debug_25 ServeLog
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
                            // ldrb w0 尾判据 → mf_debug_27 全崩。真 EntitlementManager 族
                            // getter 与语义函数同族连续(0x10009cbxx-0x10009d7xx),
                            // 距最近 S∪K 函数头 < 0x1000 才收。
                            // v2.58.29: famAnchor 改取语义函数(S)min — mf_debug_29 实锤:
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
                                if (famAnchor != UINT64_MAX && (gh < famAnchor ? famAnchor - gh : gh - famAnchor) > 0x1000) continue;   // v2.58.28: 家族窗口(双向 — 真 getter 可能在语义函数前, mf_debug_26: 0x10009cb58 < 0x10009cc70)
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
                                    // v2.58.28: patch 点 = ldrb 指令本身(不是函数头) — mf_debug_27 实锤:
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
                                // v2.58.41: prologue 紧判据(mf_debug_42 定谳 0 命中根因) —
                                //   C 版宽判据(含 sub sp/nop)回溯停在 prologue 中间(0x14208e8),
                                //   真函数头 0x14208cc 反而漏掉 → 宿主归属错 → L2 全 miss。
                                //   紧判据 = Python 版同款: stp 任意对 pre-index 到 sp + 8条内 add x29,sp。
                                // v2.58.44: L1 形态判定改读磁盘文件原始字节 — mf_debug_45 定谳:
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
                                        //   "ldur→stur 帧槽暂存"当字段装载(mf_debug_44 三点位错)。
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
                    // v2.58.23: score 排序 + top12 截断 — mf_debug_23 定谳 205 个全量
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
                            if (i < f8v2Seg && [it[@"score"] intValue] >= 3) [keep addObject:it];
                            else [pool addObject:it];
                        }
                        [pool sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                            // v2.58.27: 方向修正 — 旧写法 d<0?Descending:Ascending 把高分排到尾部,
                            // top12 removeLast 恰好删掉 ivarBoolGetter(94)真判定层, mf_debug_26 实锤
                            int d = [b[@"score"] intValue] - [a[@"score"] intValue];
                            if (d) return d < 0 ? NSOrderedAscending : NSOrderedDescending;
                            // v2.58.47: 并列改 calls 升序 — mf_debug_49(HostLog)实锤: 91分共享bool
                            //   按 calls 降序补位 = fan=211/41/26/24 基础库 helper 混进 top12;
                            //   判定函数调用点少, UI/基础库 helper 调用点多(与 F8v2 内部排序同原则)
                            int c = [a[@"calls"] intValue] - [b[@"calls"] intValue];
                            return c < 0 ? NSOrderedAscending : NSOrderedDescending;
                        }];
                        // v2.58.77: 有语义锚定就不再用噪声填满 12 — 旧行为(keep=4+fill=8)
                        //   让卡片报"12 个", 用户看着像真有 12 个候选(mf_debug_79)。
                        //   语义 ≥4 → 不填; 语义 1~3 → 补到 4; 语义 0 → 兜底填满(纯 getter app)
                        NSUInteger target = keep.count == 0 ? 12 : (keep.count >= 4 ? keep.count : 4);
                        NSUInteger room = target > keep.count ? target - keep.count : 0;
                        NSUInteger fill = MIN(pool.count, room);
                        [mo removeAllObjects];
                        [mo addObjectsFromArray:keep];
                        [mo addObjectsFromArray:[pool subarrayWithRange:NSMakeRange(0, fill)]];
                        mfLog(@"[f8v3] 截断: 语义锚定保位=%lu 槽, getter 填充=%lu (池 %lu)",
                              (unsigned long)keep.count, (unsigned long)fill, (unsigned long)pool.count);
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
    // v2.58.55: F8v2 扫描提升到框架块之前 — sk2LocalType 抑制判据需要 sk2pts(单一调用点)
    NSDictionary *f8v2 = mfReconF8v2Scan();
    NSArray *cands = f8v2[@"cands"];
    NSArray *sk2pts = f8v2[@"sk2pts"];
    BOOL sk2LocalType = NO;
    {
        NSUInteger nS = 0;
        for (NSDictionary *f in sk2pts) if ([f[@"shape"] isEqualToString:@"sk2pro"] || [f[@"shape"] isEqualToString:@"sk2get"] || [f[@"shape"] isEqualToString:@"sk2dat"] || [f[@"shape"] isEqualToString:@"sk2br"]
                ) nS++;
        if (!cloudBrands.count && !mach && nS >= 1 &&
            (mfRecFind(p, n, "verification failed") || mfRecFind(p, n, "could not be verified") || mfRecFind(p, n, "snapshot verification")))
            sk2LocalType = YES;
    }
    // F11 自研服务端权益型(v2.58.75, bplayer 案定谳): app 自带 IAP 端点(/iap/pro-status
    //   /iap/transactions 等) → 权益状态由**自家后端**下发, 本地只有 Codable 解码后的镜像字段
    //   (无代码引用=纯反射串) + 容器 Preferences 为空 → 指令级 patch 到不了判定链。
    //   判据: ①自研 /iap/* 端点 ≥1 条 ②有 VIP/权益类 Codable 字段(纯反射) ③无云 SDK 品牌
    //   → 判决「服务端权威」并抑制 sk2dat 噪声点(通用判空, 撒出去=让用户白试)。
    //   注: 提前到此计算 — merge 抑制(下方)与 verdict(末尾)都要用, 单一事实来源。
    //   v2.58.76 修正(用户定案): 旧判据用 vip_info/vip_type/vipStatus 当"权益 Codable 字段"
    //   是错的 — 那些是**百度/115 网盘** API 字段(邻居 baidu_name/netdisk_name/rt_space_info),
    //   与 Pro 无关。bplayer 实测: 4 个 Pro SKU 全在二进制, 设备 plist 零 Pro 状态键
    //   → Pro 是运行时由 StoreKit 算的**本地链**, 不是服务端下发。
    //   新判据加**本地 SK 链否决**: 只要本地 SK2 消费链在场(SK 形态 + 无锚/有锚点位),
    //   权益判定就落在本地, 绝不判"服务端权威"。
    BOOL srvSelfIap = NO;
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
                || [sh isEqualToString:@"sk2dat"] || [sh isEqualToString:@"deepslot"]) nLocalPts++;
        }
        BOOL skHere = ([skType containsString:@"SK"] && nLocalPts > 0);
        if (!cloudBrands.count && !mach && epHits >= 1 && !skHere) {
            srvSelfIap = YES;
            [lines addObject:[NSString stringWithFormat:
                @"自研 IAP 端点 %d 条 + 无本地 SK 权益链 → 权益状态由自家后端下发", epHits]];
        } else if (epHits >= 1 && skHere) {
            [lines addObject:[NSString stringWithFormat:
                @"自研 IAP 端点 %d 条 + 本地 SK 权益链在场(%lu 点) → 混合型, 以本地 StoreKit 判定为准",
                epHits, (unsigned long)nLocalPts]];
        }
    }
    NSMutableArray *entFuncs = [NSMutableArray array];
    // v2.58.74: 轮次开始 — 标记库中点位"本轮未见", merge 时置 seen, 结束剔除陈旧
    extern void mfAppPatchEntDumpsBeginRound(void);
    extern void mfAppPatchEntDumpsEndRound(void);
    mfAppPatchEntDumpsBeginRound();
    if (!sk2LocalType) {   // v2.58.55: SK2 流型时框架符号点位是噪声, 整块跳过
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
        // v2.58.55: 抑制判据已提到块外(sk2LocalType, 单一事实来源)
        if (entFuncs.count) {
            extern void mfAppPatchEntDumpsMerge(NSArray *);
            mfAppPatchEntDumpsMerge(entFuncs);
        }
        }   // v2.58.55: if (!sk2LocalType) 闭合 — SK2 流型时整块框架扫描跳过
        if (entFuncs.count) {
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
            stateKeys = mfStateProbeKeys();          // 采集(函数级变量, 局部接住教训仍守: 不在参数位内联)
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
            NSArray *sk2ptsRef = sk2pts;
            extern void mfAppPatchEntDumpsMerge(NSArray *);
            // v2.58.75: 服务端权威型抑制代码点入库 — 形态门(sk2dat)在自研服务端权益 app 上
            //   全是通用判空, 入库=让用户白试(bplayer 35 点全试不亮, mf_debug_77 实证)。
            //   sk2pro/sk2get(有字符串锚的写点/读侧)不受影响, 仅滤 sk2dat。
            // v2.58.76: sk2dat(纯指令形态门)降级为兜底 — 只要存在更强证据(语义锚定点或
            //   其他 shape), 就不再把通用判空形态点塞给用户。mf_debug_77 实证: bplayer
            //   35 个 sk2dat 全 ⚡ 不亮(它们是 ldr+cmp#0+cset ne 的通用判空, 与内购无关)。
            NSArray *mergePts = sk2ptsRef;
            {
                BOOL haveBetter = NO;
                for (NSDictionary *f in sk2ptsRef) {
                    NSString *sh = f[@"shape"] ?: @"";
                    // v2.58.78: sk2br(SKU 锚 + 分支粒度)= 强证据; 只有它才压 sk2dat
                    if ([sh isEqualToString:@"sk2br"]) { haveBetter = YES; break; }
                    if (![sh isEqualToString:@"sk2dat"] && sh.length) { haveBetter = YES; break; }
                }
                if (!haveBetter && [candsRef isKindOfClass:[NSArray class]]) {
                    for (NSDictionary *f in candsRef) {
                        if ([f[@"score"] intValue] >= 3) { haveBetter = YES; break; }
                        if ([f[@"shape"] length]) { haveBetter = YES; break; }
                    }
                }
                if (haveBetter) {
                    mergePts = [sk2ptsRef filteredArrayUsingPredicate:
                                [NSPredicate predicateWithFormat:@"shape != 'sk2dat'"]];
                    if (mergePts.count != sk2ptsRef.count)
                        [lines addObject:[NSString stringWithFormat:
                            @"形态门兜底: 已抑制 %lu 个无锚 sk2dat(通用判空形态, 有更强锚定证据时不上场)",
                            (unsigned long)(sk2ptsRef.count - mergePts.count)]];
                }
            }
            if ([mergePts isKindOfClass:[NSArray class]] && mergePts.count) {
                mfAppPatchEntDumpsMerge(mergePts);
                [entFuncs addObjectsFromArray:mergePts];
                [lines addObject:[NSString stringWithFormat:@"代码判定点: %lu 个已入库(isPro 写点/读侧 getter, 指令级 mov #1) — 见实验模拟页", (unsigned long)mergePts.count]];
            }
            // v2.58.55: SK2 流型(非云)抑制 F8v2 swifttext 点位 — mf_debug_58 用户拍板:
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
            } else if ([candsRef isKindOfClass:[NSArray class]] && candsRef.count) {
                extern void mfAppPatchEntDumpsMerge(NSArray *);
                mfAppPatchEntDumpsMerge(candsRef);
                [entFuncs addObjectsFromArray:candsRef];
                // v2.58.76: 标签按 score 来源分开报 — 旧实现一律写"F8v2 fixups 链", 实际
                //   库里多半是 f8v3(score 91~93)共享 bool getter, 把排查方向带偏(mf_debug_78)。
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
            || [f[@"shape"] isEqualToString:@"sk2dat"] || [f[@"shape"] isEqualToString:@"sk2br"]
            ) nCodePts++;
    NSString *verdict;
    if (cloud && mach)      verdict = [NSString stringWithFormat:@"%@ 云端订阅验证 + 本地许可服务器(异常端口) — 双面, mock+⚡F10 深槽点 双因子", cloudBrands.allObjects.firstObject];
    else if (cloud)         verdict = [NSString stringWithFormat:@"%@ 云端订阅验证 — mock 回包 + ⚡F10 深槽装载点 双因子解锁", cloudBrands.allObjects.firstObject];
    else if (mach)          verdict = @"本地许可服务器(异常端口 MIG, 同族架构)";
    // v2.58.65: "SK2 事务流验证型"判型已废(用户定案: 实机三轮零作用=死代码)
    else if (serverSide)    verdict = @"服务器权益型(SK+WebView 桥权益标志) — 权益在服务端会话, 本地解锁无意义, 跳过";
    // v2.58.75: 服务端权威判定型 — 优先于代码点播报(bplayer 案: 35 个形态点是通用
    //   判空噪声, 全 ⚡ 不亮已实证; 判定链在自家后端, 本地 patch 无意义)
    else if (srvSelfIap)    verdict = @"自研服务端权益型(无本地 SK 权益链, /iap/* 端点下发) — 本地解锁无意义, 跳过";
    // v2.58.65: 指令级代码判定点优先播报 — mf_debug_68 用户定案: 真正解锁的是
    //   sk2pro(写点)+sk2get(读侧) 这类**指令级 patch**, UserDefaults 直写只是辅助/部分。
    else if (nCodePts > 0)  verdict = [NSString stringWithFormat:@"代码判定型(指令级 patch %lu 点: isPro 写点/读侧 getter) — 实验模拟页⚡即解锁", (unsigned long)nCodePts];
    else if (stateType)     verdict = @"状态型(UserDefaults 实存语义key) — 🧪实验模拟→F9 状态解锁 直写";
    // v2.58.7: 纯 StoreKit 本地校验型分支(2.58.6 缺失 — SK2 明明已判定却显示"未发现订阅验证 SDK"兜底文案)
    else if (skLocal)       verdict = [NSString stringWithFormat:@"纯 StoreKit 本地校验型(%@ · %@) — 判定点已入库, 实验模拟页左划 patch", skType, validator];
    else                    verdict = @"未发现订阅验证 SDK";
    if (cloudBrands.count > 1) {
        NSString *names = [[cloudBrands.allObjects sortedArrayUsingSelector:@selector(compare)] componentsJoinedByString:@"/"];
        verdict = [verdict stringByReplacingOccurrencesOfString:cloudBrands.allObjects.firstObject
                                                     withString:[NSString stringWithFormat:@"%@(疑似多 SDK)", names]];
    }

    // v2.58.55: 本次会话侦查点位缓存 — 已废除(2.58.61 用户定案)
    //   侦查→mfAppPatchEntDumpsMerge 入库, 实验/列表 UI 只读持久层, 无"本次有效"概念
    // v2.58.74: 轮次结束 — 剔除本轮未扫出且用户未持久化的陈旧点后, 卡片"共 N 点"= 本轮真值
    mfAppPatchEntDumpsEndRound();
    return @{@"verdict": verdict, @"lines": lines,
             @"cloud": @(cloud), @"mach": @(mach), @"srv": @(serverSide), @"sk": @(skLocal),
             @"sk2": @(sk2stream),
             @"sktype": skType, @"validator": validator,
             @"entFuncs": entFuncs,
             @"stateKeys": stateKeys};   // v2.58.35: 侦查=唯一采集器 — F9 卡片吃这个, 不独立扫
}
}   // v2.58.55: F8v2 @autoreleasepool 块闭合(框架块重排时吞掉了这个 } — 平衡修复)

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
