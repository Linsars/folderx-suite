// MFSwiftMeta.m — 运行时 Swift 类方法表解析 (v2.58.87)
//
// 回答: "classdump 运行时能不能加上解析 swift 的?"
//   能 —— 而且运行时**比本地静态容易**:
//     静态文件里 vtable 槽是未绑定的 chained fixup(指向外部的显示 bind,
//     内部的是未解析值), 本地要手写 fixup 解码器才能读;
//     运行时 dyld 已全部重定位, 槽里就是现成的 IMP 指针, 直接读。
//
// 纯 Swift 类(如 HMVipProManager)的 ObjC class_ro_t.baseMethods = null,
//   所以 class-dump 只看得到字段、看不到方法 —— 方法在 Swift 元数据的 vtable 区。
//   本模块补上这一半: 枚举 vtable IMP + 用类自己的 ivar 表反汇编打语义标签。
//
// 定位策略(不硬编码偏移, 对布局不确定性鲁棒):
//   从 meta+0x48 起, 在 meta..meta+0x4000 内找**最长连续落在主二进制 __text 的
//   指针 run**, 该 run 即 vtable。(运行时全部已重定位 → run 是稠密的)

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <string.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import "MFPanel.h"

static uintptr_t g_smTextLo = 0, g_smTextHi = 0;

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
                if (strcmp(sg->segname, "__TEXT") == 0 && sg->fileoff == 0) {
                    const struct section_64 *sec = (const struct section_64 *)(sg + 1);
                    for (uint32_t s = 0; s < sg->nsects; s++, sec++) {
                        if (strcmp(sec->sectname, "__text") == 0) {
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

// 该指令是否访问 [xN,#imm]: 0=否 1=读 2=写; *outOff = 字节偏移
static int smAcc(uint32_t w, uint32_t *outOff) {
    uint32_t base = w & 0xFFC00000u;
    if ((w & 0x1Fu) == 31 || ((w >> 5) & 0x1Fu) == 31) return 0;
    uint32_t imm = (w >> 10) & 0xFFFu;
    switch (base) {
        case 0x39400000u: *outOff = imm;      return 1;   // ldrb
        case 0x39000000u: *outOff = imm;      return 2;   // strb
        case 0x79400000u: *outOff = imm * 2;  return 1;   // ldrh
        case 0x79000000u: *outOff = imm * 2;  return 2;   // strh
        case 0xB9400000u: *outOff = imm * 4;  return 1;   // ldr w
        case 0xB9000000u: *outOff = imm * 4;  return 2;   // str w
        case 0xF9400000u: *outOff = imm * 8;  return 1;   // ldr x
        case 0xF9000000u: *outOff = imm * 8;  return 2;   // str x
        default: return 0;
    }
}

static NSString *smLabelImp(uintptr_t imp, const ptrdiff_t *ivOffs, const char **ivNames, int nIv) {
    const uint32_t *code = (const uint32_t *)imp;
    NSMutableString *lbl = [NSMutableString string];
    BOOL hasRet = NO; int nIns = 0;
    for (int i = 0; i < 24; i++) {
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

// 读类描述符名 (meta+0x28..meta+0x60 扫描, 找 name 可读的那个)
static BOOL smClassIdentity(Class c, char *outName, size_t cap, uint32_t *outNim, uintptr_t *outDesc) {
    uintptr_t meta = (uintptr_t)c;
    for (uintptr_t d = 0x28; d <= 0x60; d += 8) {
        uintptr_t desc = *(const uintptr_t *)(meta + d);
        if (desc < g_smTextLo || desc > g_smTextHi + 0x800000) continue;
        int32_t nrel = 0; memcpy(&nrel, (const void *)(desc + 8), 4);
        const char *nmp = (const char *)(desc + 8 + (intptr_t)nrel);
        if ((uintptr_t)nmp < g_smTextLo) continue;
        char tmp[256]; tmp[0] = 0;
        for (int i = 0; i < 255; i++) {
            char ch = nmp[i];
            if (!ch) break;
            if (ch < 32 || ch > 126) { tmp[0] = 0; break; }
            tmp[i] = ch; tmp[i+1] = 0;
        }
        if (!tmp[0]) continue;
        uint32_t nim = 0; memcpy(&nim, (const void *)(desc + 28), 4);
        if (nim == 0 || nim > 4000) continue;
        strncpy(outName, tmp, cap - 1); outName[cap-1] = 0;
        *outNim = nim; *outDesc = desc;
        return YES;
    }
    return NO;
}

// 返回该类的 Swift 方法表文本 (nil = 非 Swift 类 / 无 vtable)
NSString *mfSwiftMethodTable(Class c) {
    if (!c) return nil;
    smTextRange();
    if (!g_smTextLo) return nil;

    char cls[256]; uint32_t nim = 0; uintptr_t desc = 0;
    if (!smClassIdentity(c, cls, sizeof(cls), &nim, &desc)) return nil;

    uintptr_t meta = (uintptr_t)c;
    // 找最长连续 __text 指针 run = vtable
    uintptr_t bestStart = 0; int bestLen = 0;
    uintptr_t runStart = 0; int runLen = 0;
    for (uintptr_t p = meta + 0x48; p < meta + 0x4000; p += 8) {
        uintptr_t v = *(const uintptr_t *)p;
        if (v >= g_smTextLo && v < g_smTextHi) {
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
    for (int k = 0; k < bestLen; k++) {
        uintptr_t imp = *(const uintptr_t *)(bestStart + (uintptr_t)k * 8);
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
