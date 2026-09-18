// MFSwiftMeta.m — 运行时 Swift 类方法表解析 (v2.58.88)
//
// 回答: "classdump 运行时能不能加上解析 swift 的?"
//   能 — 且运行时比本地静态省事: 静态 vtable 槽是未绑定 chained fixup(需手写解码器),
//   运行时 dyld 已重定位, 槽里就是现成 IMP 指针。
//
// 纯 Swift 类(HMVipProManager)的 class_ro_t.baseMethods=null → class-dump 只见字段,
//   方法在 Swift 元数据 vtable 里。本模块补上这一半。
//
// ★ v2.58.88 崩溃修复 (mf_debug_90: 2.58.87 出包即闪退):
//   v2.58.87 用裸指针解引用(*(uintptr_t*)addr / nmp[i] 逐字节), 全部是野读,
//   一旦越界就是 SIGSEGV/SIGBUS — **@try 接不住**, app 直接死。
//   本版: 所有内存读取一律经 smRd()(mach_vm_read_overwrite), 读失败返回 NO 并跳过;
//   任何一步拿不到数据都只是"没有输出", 绝不崩。宁可少输出, 不可崩 app。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <string.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import "MFPanel.h"

static uintptr_t g_smTextLo = 0, g_smTextHi = 0;

// 安全读: 失败绝不崩 (vm_read_overwrite 对未映射地址返回 KERN_INVALID_ADDRESS)
static BOOL smRd(uintptr_t addr, void *dst, size_t len) {
    if (!addr || !len) return NO;
    mach_vm_size_t out = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
                                              (mach_vm_address_t)addr,
                                              (mach_vm_size_t)len,
                                              (mach_vm_address_t)dst, &out);
    return (kr == KERN_SUCCESS && out == len);
}
static BOOL smRd32(uintptr_t addr, uint32_t *out) { return smRd(addr, out, 4); }
static BOOL smRdI32(uintptr_t addr, int32_t *out) { return smRd(addr, out, 4); }
static BOOL smRd64(uintptr_t addr, uint64_t *out) { return smRd(addr, out, 8); }

// 安全读 C 字符串 (逐字节 vm_read, 有上限)
static BOOL smRdStr(uintptr_t addr, char *dst, size_t cap) {
    if (!addr || !cap) return NO;
    dst[0] = 0;
    for (size_t i = 0; i + 1 < cap; i++) {
        char ch = 0;
        if (!smRd(addr + i, &ch, 1)) return i > 0;   // 读到映射边界: 有内容就算成功
        if (!ch) return i > 0;
        if (ch < 32 || ch > 126) return NO;          // 非可打印 → 判为坏指针
        dst[i] = ch; dst[i + 1] = 0;
    }
    return YES;
}

static void smTextRange(void) {
    if (g_smTextLo) return;
    uint32_t ic = _dyld_image_count();
    for (uint32_t i = 0; i < ic && !g_smTextLo; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh) continue;
        const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
        const uint8_t *p = (const uint8_t *)(h + 1);
        const uint8_t *end = (const uint8_t *)mh + sizeof(struct mach_header_64) + h->sizeofcmds;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        for (uint32_t k = 0; k < h->ncmds; k++) {
            if (p + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize < sizeof(struct load_command) || p + lc->cmdsize > end) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
                if (sg->fileoff == 0 && sg->vmaddr == 0) { p += lc->cmdsize; continue; }   // __PAGEZERO
                if (strncmp(sg->segname, "__TEXT", 16) == 0 && sg->fileoff == 0) {
                    const struct section_64 *sec = (const struct section_64 *)(sg + 1);
                    for (uint32_t s = 0; s < sg->nsects; s++, sec++) {
                        if (strncmp(sec->sectname, "__text", 16) == 0) {
                            g_smTextLo = (uintptr_t)sec->addr + slide;
                            g_smTextHi = g_smTextLo + sec->size;
                        }
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
}

// [xN,#imm] 访问: 0=否 1=读 2=写
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

static NSString *smLabelImp(uintptr_t imp, const ptrdiff_t *ivOffs, const char **ivNames, int nIv) {
    if (imp < g_smTextLo || imp > g_smTextHi) return nil;
    uint32_t code[24];
    size_t need = sizeof(code);
    if (g_smTextHi - imp < need) need = (size_t)(g_smTextHi - imp);
    if (need < 16) return nil;
    if (!smRd(imp, code, need)) return nil;               // ★ 安全读, 越界不崩
    int nInsMax = (int)(need / 4);
    NSMutableString *lbl = [NSMutableString string];
    BOOL hasRet = NO; int nIns = 0;
    for (int i = 0; i < nInsMax; i++) {
        uint32_t w = code[i]; nIns++;
        if (w == 0xD65F03C0u) { hasRet = YES; break; }
        uint32_t off = 0;
        int acc = smAcc(w, &off);
        if (!acc) continue;
        for (int k = 0; k < nIv; k++) {
            if ((ptrdiff_t)off != ivOffs[k]) continue;
            NSString *piece = [NSString stringWithFormat:@"%s %s", acc == 1 ? "reads" : "writes", ivNames[k]];
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

// 读类描述符名; 成功则输出 name/numImmediateMembers
static BOOL smClassIdentity(Class c, char *outName, size_t cap, uint32_t *outNim) {
    uintptr_t meta = (uintptr_t)c;
    for (uintptr_t d = 0x28; d <= 0x60; d += 8) {
        uintptr_t desc = 0;
        if (!smRd64(meta + d, &desc)) continue;
        if (desc < g_smTextLo || desc > g_smTextHi + 0x1000000) continue;
        int32_t nrel = 0;
        if (!smRdI32(desc + 8, &nrel)) continue;
        uintptr_t nmp = desc + 8 + (intptr_t)nrel;
        if (nmp < g_smTextLo || nmp > g_smTextHi + 0x1000000) continue;
        if (!smRdStr(nmp, outName, cap)) continue;
        uint32_t nim = 0;
        if (!smRd32(desc + 28, &nim)) continue;
        if (nim == 0 || nim > 4000) continue;
        *outNim = nim;
        return YES;
    }
    return NO;
}

// 返回该类的 Swift 方法表文本 (nil = 非 Swift 类 / 无数据 / 读失败)
NSString *mfSwiftMethodTable(Class c) {
    if (!c) return nil;
    smTextRange();
    if (!g_smTextLo) return nil;

    char cls[256]; uint32_t nim = 0;
    if (!smClassIdentity(c, cls, sizeof(cls), &nim)) return nil;

    uintptr_t meta = (uintptr_t)c;
    // 找最长连续落在 __text 的指针 run = vtable (运行时已重定位 → run 稠密)
    // ★ 每槽独立 smRd64, 越界槽自然失败并被当作 run 断开, 不会崩
    uintptr_t bestStart = 0, runStart = 0; int bestLen = 0, runLen = 0;
    int scanned = 0;
    for (uintptr_t p = meta + 0x48; p < meta + 0x1000 && scanned < 512; p += 8, scanned++) {
        uintptr_t v = 0;
        if (smRd64(p, &v) && v >= g_smTextLo && v < g_smTextHi) {
            if (!runLen) runStart = p;
            runLen++;
            if (runLen > bestLen) { bestLen = runLen; bestStart = runStart; }
        } else runLen = 0;
    }
    if (bestLen < 3) return nil;

    unsigned int nIv = 0;
    Ivar *ivs = class_copyIvarList(c, &nIv);
    ptrdiff_t offs[64]; const char *names[64]; int n = 0;
    for (unsigned int i = 0; ivs && i < nIv && n < 64; i++) {
        const char *in = ivar_getName(ivs[i]);
        if (!in) continue;
        offs[n] = ivar_getOffset(ivs[i]); names[n] = in; n++;
    }
    if (ivs) free(ivs);

    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"    // Swift vtable: name=%s numImmediateMembers=%u run=%d@meta+%#llx ivars=%d\n",
         cls, nim, bestLen, (unsigned long long)(bestStart - meta), n];
    int tagged = 0;
    for (int k = 0; k < bestLen && k < 256; k++) {
        uintptr_t imp = 0;
        if (!smRd64(bestStart + (uintptr_t)k * 8, &imp)) break;
        NSString *lbl = smLabelImp(imp, offs, names, n);
        if (lbl) {
            tagged++;
            [out appendFormat:@"    imp[%d] %#llx  %@\n", k, (unsigned long long)imp, lbl];
        } else if (k < 8) {
            [out appendFormat:@"    imp[%d] %#llx\n", k, (unsigned long long)imp];
        }
    }
    [out appendFormat:@"    // 小结: vtable IMP=%d, 带权益字段标签=%d\n", bestLen, tagged];
    return out;
}
