// MFSwiftMeta.m — Swift 类方法表解析 (v2.58.91, 零 ObjC runtime 依赖)
//
// ★★ 为什么不用 objc_getClass / objc_copyClassList:
//   iOS26 SDK 下 force-realize 带泛型 conformance 的 Swift 类会走 _getWitnessTable 崩
//   (v2.52.2 已记述; mf_debug_92 实测 CLASSDUMP names=61121 后即崩)。
//   本模块改为**纯内存解析**: 已知 Swift 描述符地址 → 在 __DATA 里扫出 metadata
//   → 解析 class_ro_t/ivar 表/vtable。全程只做 vm_read_overwrite, 不碰 ObjC runtime,
//   不触发任何 realize → 结构上不可能因此崩溃。
//
// 布局(实测 bplayer 的 HMVipProManager, arm64):
//   meta + 0x20 → class_ro_t | flags   (ObjC 兼容头, 含 ivar 表)
//   meta + 0x40 → Swift class descriptor (description 槽)
//   meta + 0x48 → 之后是 immediate members; 方法 IMP 混在 8 字节槽里
//   故: ① 用 desc 反查 meta(扫 __DATA 找指向 desc 的槽, meta = 槽 - 0x40)
//       ② 在 meta+0x48 .. meta+0x1000 找最长连续落在 __text 的指针 run = vtable
//       ③ 用该类的 ivar 偏移表(从 ro+48 解析)给每个 IMP 打语义标签

#import <Foundation/Foundation.h>
#import <string.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import "MFPanel.h"

#define SM_MAXSEG 8
static uintptr_t g_segAddr[SM_MAXSEG], g_segSize[SM_MAXSEG];
static int g_segN = 0;
static uintptr_t g_textLo = 0, g_textHi = 0;

// ---- 安全读 (失败绝不崩) ----
static BOOL smRd(uintptr_t addr, void *dst, size_t len) {
    if (!addr || !len) return NO;
    vm_size_t out = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                         (vm_size_t)len, (vm_address_t)dst, &out);
    return (kr == KERN_SUCCESS && out == len);
}
static BOOL smRd32(uintptr_t a, uint32_t *o) { return smRd(a, o, 4); }
static BOOL smRdI32(uintptr_t a, int32_t *o) { return smRd(a, o, 4); }
static BOOL smRd64(uintptr_t a, uintptr_t *o) { return smRd(a, o, sizeof(uintptr_t)); }
static BOOL smRdStr(uintptr_t addr, char *dst, size_t cap) {
    if (!addr || cap < 2) return NO;
    dst[0] = 0;
    for (size_t i = 0; i + 1 < cap; i++) {
        char ch = 0;
        if (!smRd(addr + i, &ch, 1)) return i > 0;
        if (!ch) return i > 0;
        if (ch < 32 || ch > 126) return NO;
        dst[i] = ch; dst[i + 1] = 0;
    }
    return YES;
}

// ---- 主镜像段表 + __text 范围 ----
static void smInit(void) {
    if (g_segN) return;
    uint32_t ic = _dyld_image_count();
    for (uint32_t i = 0; i < ic && !g_segN; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh) continue;
        const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
        const uint8_t *p = (const uint8_t *)(h + 1);
        const uint8_t *end = (const uint8_t *)mh + sizeof(struct mach_header_64) + h->sizeofcmds;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        BOOL isMain = NO;
        for (uint32_t k = 0; k < h->ncmds; k++) {
            if (p + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize < sizeof(struct load_command) || p + lc->cmdsize > end) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
                if (sg->fileoff == 0 && sg->vmaddr == 0) { p += lc->cmdsize; continue; }  // __PAGEZERO
                if (strncmp(sg->segname, "__TEXT", 16) == 0 && sg->fileoff == 0) isMain = YES;
                // v2.58.91: 只收 __DATA* 段做 metadata 反查 —— class metadata 在 __DATA 族,
                //   而 __TEXT 有 21MB, 扫它纯属浪费且拖慢面板。
                if (isMain && sg->vmsize > 0 && g_segN < SM_MAXSEG &&
                    strncmp(sg->segname, "__DATA", 6) == 0) {
                    g_segAddr[g_segN] = (uintptr_t)sg->vmaddr + slide;
                    g_segSize[g_segN] = sg->vmsize;
                    g_segN++;
                }
                if (isMain && strncmp(sg->segname, "__TEXT", 16) == 0) {
                    const struct section_64 *sec = (const struct section_64 *)(sg + 1);
                    for (uint32_t s = 0; s < sg->nsects; s++, sec++) {
                        if (strncmp(sec->sectname, "__text", 16) == 0) {
                            g_textLo = (uintptr_t)sec->addr + slide;
                            g_textHi = g_textLo + sec->size;
                        }
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
}

// ---- 由 Swift 描述符反查 metadata (扫 __DATA 段找指向 desc 的槽) ----
static uintptr_t smMetaForDesc(uintptr_t desc) {
    if (!desc) return 0;
    static uint8_t buf[64 * 1024];
    for (int s = 0; s < g_segN; s++) {
        uintptr_t a = g_segAddr[s], sz = g_segSize[s];
        if (sz < 0x1000 || sz > 0x4000000) continue;          // 跳过 __TEXT 等巨大段
        for (uintptr_t off = 0; off + 8 <= sz; off += sizeof(buf)) {
            size_t want = sizeof(buf);
            if (off + want > sz) want = (size_t)(sz - off);
            if (!smRd(a + off, buf, want)) continue;          // 未映射就跳过
            for (size_t i = 0; i + 8 <= want; i += 8) {
                uintptr_t v = 0;
                memcpy(&v, buf + i, 8);
                if (v != desc) continue;
                uintptr_t cand = a + off + i - 0x40;          // meta = 槽 - 0x40
                uintptr_t chk = 0;
                if (smRd64(cand + 0x40, &chk) && chk == desc) return cand;
            }
        }
    }
    return 0;
}

// ---- 从 meta 解析该类自己的 ivar 偏移表 (标签用) ----
static int smIvarsFromMeta(uintptr_t meta, ptrdiff_t *offs, const char **names, int cap) {
    uintptr_t ro = 0;
    if (!smRd64(meta + 0x20, &ro)) return 0;
    ro &= ~(uintptr_t)7;
    uintptr_t ivp = 0;
    if (!smRd64(ro + 48, &ivp) || !ivp) return 0;
    uint32_t entsize = 0, count = 0;
    if (!smRd32(ivp, &entsize) || !smRd32(ivp + 4, &count)) return 0;
    if (count == 0 || count > 256) return 0;
    if (entsize < 12 || entsize > 64) return 0;
    int n = 0;
    for (uint32_t k = 0; k < count && n < cap; k++) {
        uintptr_t e = ivp + 8 + (uintptr_t)k * entsize;
        uintptr_t offPtr = 0, namePtr = 0;
        if (!smRd64(e, &offPtr) || !smRd64(e + 8, &namePtr)) continue;
        int32_t ov = 0;
        if (!offPtr || !smRdI32(offPtr, &ov)) continue;
        char nb[128];
        if (!smRdStr(namePtr, nb, sizeof(nb))) continue;
        offs[n] = (ptrdiff_t)ov;
        names[n] = strdup(nb);            // 调用方负责 free
        if (names[n]) n++;
    }
    return n;
}

// ---- [xN,#imm] 访问判定 ----
static int smAcc(uint32_t w, uint32_t *outOff) {
    uint32_t base = w & 0xFFC00000u;
    if ((w & 0x1Fu) == 31 || ((w >> 5) & 0x1Fu) == 31) return 0;
    uint32_t imm = (w >> 10) & 0xFFFu;
    switch (base) {
        case 0x39400000u: *outOff = imm;      return 1;
        case 0x39000000u: *outOff = imm;      return 2;
        case 0x79400000u: *outOff = imm * 2;  return 1;
        case 0x79000000u: *outOff = imm * 2;  return 2;
        case 0xB9400000u: *outOff = imm * 4;  return 1;
        case 0xB9000000u: *outOff = imm * 4;  return 2;
        case 0xF9400000u: *outOff = imm * 8;  return 1;
        case 0xF9000000u: *outOff = imm * 8;  return 2;
        default: return 0;
    }
}

static NSString *smLabelImp(uintptr_t imp, const ptrdiff_t *offs, const char **names, int nIv) {
    if (imp < g_textLo || imp >= g_textHi) return nil;
    uint32_t code[24];
    size_t need = sizeof(code);
    if (g_textHi - imp < need) need = (size_t)(g_textHi - imp);
    if (need < 16) return nil;
    if (!smRd(imp, code, need)) return nil;
    NSMutableString *lbl = [NSMutableString string];
    BOOL hasRet = NO; int nIns = 0, nInsMax = (int)(need / 4);
    for (int i = 0; i < nInsMax; i++) {
        uint32_t w = code[i]; nIns++;
        if (w == 0xD65F03C0u) { hasRet = YES; break; }
        uint32_t off = 0;
        int acc = smAcc(w, &off);
        if (!acc) continue;
        for (int k = 0; k < nIv; k++) {
            if ((ptrdiff_t)off != offs[k]) continue;
            NSString *piece = [NSString stringWithFormat:@"%s %s", acc == 1 ? "reads" : "writes", names[k]];
            if (![lbl containsString:piece]) {
                if (lbl.length) [lbl appendString:@", "];
                [lbl appendString:piece];
            }
            break;
        }
    }
    if (!lbl.length) return nil;
    if (hasRet && nIns <= 10) [lbl appendString:@" (accessor)"];
    return lbl;
}

// ---- 主入口: 由描述符地址产出方法表文本 (nil = 无数据/读失败, 绝不崩) ----
NSString *mfSwiftMethodTableForDescriptor(uintptr_t desc, const char *clsName) {
    smInit();
    if (!g_textLo || !desc) return nil;
    uintptr_t meta = smMetaForDesc(desc);
    if (!meta) return nil;

    ptrdiff_t offs[64]; const char *names[64];
    int nIv = smIvarsFromMeta(meta, offs, names, 64);

    // vtable: meta+0x48 起找最长连续 __text 指针 run (每槽独立安全读)
    uintptr_t bestStart = 0, runStart = 0; int bestLen = 0, runLen = 0;
    for (uintptr_t p = meta + 0x48, e = meta + 0x1000; p < e; p += 8) {
        uintptr_t v = 0;
        if (smRd64(p, &v) && v >= g_textLo && v < g_textHi) {
            if (!runLen) runStart = p;
            runLen++;
            if (runLen > bestLen) { bestLen = runLen; bestStart = runStart; }
        } else runLen = 0;
    }

    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"    // Swift meta=%#llx desc=%#llx ivars=%d vtableRun=%d@meta+%#llx\n",
         (unsigned long long)meta, (unsigned long long)desc, nIv, bestLen,
         (unsigned long long)(bestStart ? bestStart - meta : 0)];
    if (bestLen >= 3) {
        int tagged = 0;
        for (int k = 0; k < bestLen && k < 256; k++) {
            uintptr_t imp = 0;
            if (!smRd64(bestStart + (uintptr_t)k * 8, &imp)) break;
            NSString *lbl = smLabelImp(imp, offs, names, nIv);
            if (lbl) {
                tagged++;
                [out appendFormat:@"    imp[%d] %#llx  %@\n", k, (unsigned long long)imp, lbl];
            } else if (k < 10) {
                [out appendFormat:@"    imp[%d] %#llx\n", k, (unsigned long long)imp];
            }
        }
        [out appendFormat:@"    // 小结: vtable IMP=%d, 带权益字段标签=%d\n", bestLen, tagged];
    }
    // 无 vtable run 时, 退化为打印该类 ivar 表 (仍有价值: 验证 0x6d0 归属)
    if (bestLen < 3) {
        for (int k = 0; k < nIv; k++)
            [out appendFormat:@"    ivar %s off=%#lx\n", names[k], (long)offs[k]];
    }
    for (int k = 0; k < nIv; k++) if (names[k]) free((void *)names[k]);
    return out;
}
