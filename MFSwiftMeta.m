// MFSwiftMeta.m — Swift 类方法表解析 (v2.58.97, 零 ObjC realize 风险)
//
// v2.58.97 修两处 (mf_debug_94 实测):
//   ① `ivars=0` → 标签全空。根因: 我从 meta+0x20 解 class_ro_t 再解 ivar_list 失败。
//      改用 **class_copyIvarList(Class)** —— 类对象本来就有, 且 mf_debug_94 已证明它可信
//      (13 个 ivar 名字+偏移全对: _isVipPro=1744=0x6d0)。
//   ② `vtableRun=8` → 只找到 8 个。根因: Swift vtable 里大量槽是 `_swift_deletedMethodError`
//      (bind 修复项, 不是 __text 指针), 把"最长连续 run"切碎。
//      改用 **允许间隔扫描**: 在 vtable 区内收集全部落在 __text 的指针。
//
// 布局(实测): meta+0x20 = class_ro_t, meta+0x40 = Swift 描述符, 之后是字段偏移向量 + vtable。
// 槽可能是三种形态: 裸指针(运行时已重定位) / chained fixup 值(需掩码+基址) / bind(非代码)。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <string.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import "MFPanel.h"

static uintptr_t g_textLo = 0, g_textHi = 0;

static BOOL smRd(uintptr_t addr, void *dst, size_t len) {
    if (!addr || !len) return NO;
    vm_size_t out = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                         (vm_size_t)len, (vm_address_t)dst, &out);
    return (kr == KERN_SUCCESS && out == len);
}
static BOOL smRd32(uintptr_t a, uint32_t *o) { return smRd(a, o, 4); }
static BOOL smRd64(uintptr_t a, uintptr_t *o) { return smRd(a, o, sizeof(uintptr_t)); }

static void smTextRange(void) {
    if (g_textLo) return;
    uint32_t ic = _dyld_image_count();
    for (uint32_t i = 0; i < ic && !g_textLo; i++) {
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
                if (sg->fileoff == 0 && sg->vmaddr == 0) { p += lc->cmdsize; continue; }
                if (strncmp(sg->segname, "__TEXT", 16) == 0 && sg->fileoff == 0) {
                    isMain = YES;
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
        if (isMain && !g_textLo) continue;
    }
}

// 把槽值归一化为代码地址 (裸指针 / chained fixup 两种形态都试); 0 = 不是代码指针
static uintptr_t smCodeAddr(uintptr_t v) {
    if (!v) return 0;
    if (v & (1ULL << 63)) return 0;                 // bind — 非本地代码
    if (v >= g_textLo && v < g_textHi) return v;    // 运行时裸指针
    uintptr_t c36 = v & 0xFFFFFFFFFULL;             // chained fixup: 低位 36 bit + 镜像基址
    if (c36) {
        uintptr_t t = c36 + 0x100000000ULL;
        if (t >= g_textLo && t < g_textHi) return t;
    }
    uintptr_t c51 = v & 0x7FFFFFFFFFFFFULL;
    if (c51 >= g_textLo && c51 < g_textHi) return c51;
    return 0;
}

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

// 扫 IMP 函数体, 归纳它读了/写了哪些权益 ivar
static NSString *smLabelImp(uintptr_t imp, const ptrdiff_t *ivOffs, const char **ivNames, int nIv) {
    if (imp < g_textLo || imp >= g_textHi) return nil;
    uint32_t code[96];
    size_t need = sizeof(code);
    if (g_textHi - imp < need) need = (size_t)(g_textHi - imp);
    if (need < 16) return nil;
    if (!smRd(imp, code, need)) return nil;
    NSMutableString *lbl = [NSMutableString string];
    BOOL hasRet = NO; int nIns = 0, nMax = (int)(need / 4);
    for (int i = 0; i < nMax; i++) {
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
    if (hasRet && nIns <= 12) [lbl appendString:@" (accessor)"];
    return lbl;
}

// ---- 主入口: meta = Class 指针 (Swift 类的 Class 对象就是 metadata) ----
NSString *mfSwiftMethodTableForMeta(uintptr_t meta, const char *clsName) {
    smTextRange();
    if (!g_textLo || !meta) return nil;
    // ARC 下 uintptr_t → Class 需走 __bridge (mfSwiftMethodTableForMeta 是底层入口,
    //   调用方传的就是类指针; 这里只用来调 class_copyIvarList)
    Class c = (__bridge Class)(void *)meta;

    // ① ivar 表: 直接用 runtime API (mf_debug_94 证明可信), 不自己解 ro
    unsigned int nIv0 = 0;
    Ivar *ivs = class_copyIvarList(c, &nIv0);
    ptrdiff_t offs[64]; const char *names[64]; int nIv = 0;
    for (unsigned int i = 0; ivs && i < nIv0 && nIv < 64; i++) {
        const char *in = ivar_getName(ivs[i]);
        if (!in) continue;
        offs[nIv] = ivar_getOffset(ivs[i]);
        names[nIv] = strdup(in);
        if (names[nIv]) nIv++;
    }
    if (ivs) free(ivs);

    // ② 描述符 → numImmediateMembers (决定扫描跨度)
    //   运行时 dyld 已重定位, meta+0x40 应是裸指针; 若不像, 试 chained fixup 掩码形态。
    uintptr_t desc = 0;
    uint32_t nim = 0;
    if (smRd64(meta + 0x40, &desc) && desc) {
        uintptr_t d = desc;
        if (d < 0x100000000ULL || d > 0x200000000ULL) {
            uintptr_t t = (desc & 0xFFFFFFFFFULL) + 0x100000000ULL;
            if (t >= 0x100000000ULL && t <= 0x200000000ULL) d = t;
        }
        if (d >= 0x100000000ULL && d <= 0x200000000ULL) smRd32(d + 28, &nim);
    }
    if (nim == 0 || nim > 4000) nim = 256;

    // ③ 允许间隔地收集 vtable 区内所有代码指针 (deleted-method 槽会打断连续 run)
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"    // Swift meta=%#llx nim=%u ivars=%d\n",
         (unsigned long long)meta, nim, nIv];
    int found = 0, tagged = 0;
    uintptr_t base = meta + 0x48;
    uintptr_t endP = base + ((uintptr_t)nim + 128) * 8;
    for (uintptr_t p = base; p < endP; p += 8) {
        uintptr_t v = 0;
        if (!smRd64(p, &v)) break;
        uintptr_t imp = smCodeAddr(v);
        if (!imp) continue;
        found++;
        NSString *lbl = smLabelImp(imp, offs, names, nIv);
        if (lbl) {
            tagged++;
            [out appendFormat:@"    slot[+%#lx] %#llx  %@\n", (long)(p - meta), (unsigned long long)imp, lbl];
        } else if (found <= 12) {
            [out appendFormat:@"    slot[+%#lx] %#llx\n", (long)(p - meta), (unsigned long long)imp];
        }
    }
    [out appendFormat:@"    // 小结: 代码槽=%d, 带权益字段标签=%d\n", found, tagged];
    for (int k = 0; k < nIv; k++) free((void *)names[k]);
    return (found ? out : nil);
}

NSString *mfSwiftMethodTable(void *cls) {
    return mfSwiftMethodTableForMeta((uintptr_t)cls, NULL);
}

// ---- 兼容入口: classdump 只有描述符地址时用 (mf_debug_94 起主路径已改为直接传 Class) ----
//   由描述符反查 metadata: 扫可写段找指向 desc 的槽, meta = 槽 - 0x40。
//   运行时该槽是裸指针; 静态是 chained fixup 值 → 双掩码都试。
NSString *mfSwiftMethodTableForDescriptor(uintptr_t desc, const char *clsName) {
    smTextRange();
    if (!g_textLo || !desc) return nil;
    uintptr_t meta = 0;
    vm_address_t addr = 0;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t infoCnt;
    mach_port_t objName = MACH_PORT_NULL;
    uint8_t buf[65536];
    int guard = 0;
    while (!meta && guard++ < 4096) {
        infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
        kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info, &infoCnt, &objName);
        if (kr != KERN_SUCCESS) break;
        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE)) {
            uintptr_t p = (uintptr_t)addr, endp = (uintptr_t)addr + size;
            while (p + 8 <= endp && !meta) {
                size_t want = sizeof(buf);
                if (p + want > endp) want = (size_t)(endp - p);
                if (want < 8) break;
                vm_size_t got = 0;
                if (vm_read_overwrite(mach_task_self(), (vm_address_t)p, (vm_size_t)want,
                                      (vm_address_t)buf, &got) != KERN_SUCCESS || got < 8) break;
                for (size_t i = 0; i + 8 <= got; i += 8) {
                    uintptr_t v = 0;
                    memcpy(&v, buf + i, 8);
                    uintptr_t c36 = v & 0xFFFFFFFFFULL, c51 = v & 0x7FFFFFFFFFFFFULL;
                    if (v != desc && c36 != desc && c51 != desc) continue;
                    uintptr_t cand = p + i - 0x40;
                    uintptr_t chk = 0;
                    if (smRd64(cand + 0x40, &chk)) {
                        uintptr_t k36 = chk & 0xFFFFFFFFFULL, k51 = chk & 0x7FFFFFFFFFFFFULL;
                        if (chk == desc || k36 == desc || k51 == desc) { meta = cand; break; }
                    }
                }
                p += got;
            }
        }
        addr += size;
    }
    if (!meta) return nil;
    return mfSwiftMethodTableForMeta(meta, clsName);
}
