// MFCompatPatcher.m — iOS 18+ SDK 向下兼容补丁（CompatPatcher.dylib）
//
// 场景: Xcode 26(Swift 6.2) 编译的 app 在 iOS 17 启动即 SIGSEGV pc=0。
// 根因: 生成代码引用 4 个 iOS 18+ Swift runtime 弱符号, iOS 17 libswiftCore 缺失
//       → dyld 绑 GOT=0 → 无判空调用点 bl 0 崩。
//
// 方案 v3(不依赖 chained fixups blob, 与安装方式/加密无关):
//   1. 按 executablePath 匹配主镜像(注入进程里 image 0 不可靠)
//   2. LC_DYSYMTAB 间接符号表: __stubs 每槽 12B, 按符号名找到目标 stub
//   3. 解码 stub 的 adrp+ldr 两条指令 → GOT 槽运行时地址
//   4. mprotect 数据页 → 写等价实现(getExtended→6参版/malloc/ret1/noop)
//
// 诊断: 偏好 mfCompatDiag(跨进程可读, 崩溃不失) + 沙盒 Documents/mfcompat.log

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

#define MF_PREF_PATH "/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"

// ---- 诊断(双通道) ----
// v2.17.3: root 进程(TrollStore 等)禁写——root 写会整文件变 root:0600,
// SpringBoard/所有 app(mobile)从此读不到 prefs → FolderX 全静默失效实录
static void mfCompatDiag(NSString *step, NSString *detail) {
    @autoreleasepool {
        if (getuid() == 0) return;
        // 闸门1: 系统(com.apple.*)进程零接触 prefs
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        if (!bid || [bid.lowercaseString hasPrefix:@"com.apple."]) return;
        NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:@MF_PREF_PATH] mutableCopy];
        // 闸门2: 读失败(沙盒/权限) → 不写回, 保护已有设置不被覆盖
        if (!prefs) return;
        NSMutableDictionary *diag = [prefs[@"mfCompatDiag"] mutableCopy] ?: [NSMutableDictionary dictionary];
        diag[step] = detail ?: @"";
        diag[@"last_pid"] = @(getpid());
        diag[@"last_bid"] = bid;
        prefs[@"mfCompatDiag"] = diag;
        [prefs writeToFile:@MF_PREF_PATH atomically:YES];
    }
}
static void mfCompatLog(const char *fmt, ...) {
    @autoreleasepool {
        va_list ap; va_start(ap, fmt);
        char buf[512]; vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
        NSString *home = NSHomeDirectory();
        if (home) {
            FILE *f = fopen([[home stringByAppendingPathComponent:@"Documents/mfcompat.log"] UTF8String], "a");
            if (f) { fprintf(f, "%s\n", buf); fclose(f); }
        }
    }
}

// ---- 4 符号 ----
static const char *kTgt[4] = {
    "_swift_getExtendedFunctionTypeMetadata",
    "_swift_coroFrameAlloc",
    "_swift_stdlib_isStackAllocationSafe",
    "_swift_task_deinitOnExecutor",
};
static void *g_impl[4];
static int compat_isStackSafe(void *p, size_t align) { return 1; }
static void compat_deinitNoop(void *obj, void *work, void *exec, void *flags) {}

// ---- 主镜像(按 executablePath 匹配, 不信 image 0) ----
static const struct mach_header_64 *g_mh;
static intptr_t g_slide;
static uint32_t g_imgIndex;

static BOOL mfFindMainImage(void) {
    NSString *exe = [[NSBundle mainBundle] executablePath];
    const char *exeC = exe.fileSystemRepresentation;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strcmp(name, exeC) == 0) {
            g_mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
            g_slide = _dyld_get_image_vmaddr_slide(i);
            g_imgIndex = i;
            return YES;
        }
    }
    // 兜底: 找 MH_EXECUTE
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE) {
            g_mh = h;
            g_slide = _dyld_get_image_vmaddr_slide(i);
            g_imgIndex = i;
            return YES;
        }
    }
    return NO;
}

// ---- LC 采集: 段表 / symtab / dysymtab / __stubs section ----
typedef struct { uint64_t vmaddr, vmsize, fileoff, filesize; } MFseg;
static MFseg g_segs[16];
static int g_segCount;
static uint32_t g_symoff, g_nsyms, g_stroff;
static uint32_t g_indirectoff, g_nindirect;
static uint64_t g_stubsAddr, g_stubsSize;
static uint32_t g_stubsRes1;
static BOOL g_hasStubs, g_hasSymtab, g_hasIndirect;
// __got/__auth_got 扩展(数据指针类符号)
#define MF_MAX_GOT 8
static uint64_t g_gotAddr[MF_MAX_GOT]; static uint64_t g_gotSize[MF_MAX_GOT];
static uint32_t g_gotRes1[MF_MAX_GOT]; static int g_gotCount;

static uint8_t *mfFileOffToPtr(uint64_t fileoff) {
    for (int i = 0; i < g_segCount; i++) {
        if (fileoff >= g_segs[i].fileoff && fileoff < g_segs[i].fileoff + g_segs[i].filesize) {
            return (uint8_t *)(g_slide + g_segs[i].vmaddr + (fileoff - g_segs[i].fileoff));
        }
    }
    return NULL;
}

static void mfParseLcs(void) {
    g_segCount = 0;
    g_hasStubs = g_hasSymtab = g_hasIndirect = NO;
    const uint8_t *base = (const uint8_t *)g_mh;
    uint32_t off = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < g_mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)(base + off);
        uint32_t cs  = *(uint32_t *)(base + off + 4);
        if (cmd == LC_SEGMENT_64 && g_segCount < 16) {
            MFseg s;
            memcpy(&s.vmaddr,  base + off + 24, 8);
            memcpy(&s.vmsize,  base + off + 32, 8);
            memcpy(&s.fileoff, base + off + 40, 8);
            memcpy(&s.filesize, base + off + 48, 8);
            g_segs[g_segCount++] = s;
            // sections
            uint32_t nsects = *(uint32_t *)(base + off + 64);
            uint32_t so = off + 72;
            for (uint32_t k = 0; k < nsects; k++) {
                char sect[17]; memcpy(sect, base + so, 16); sect[16] = 0;
                char segname[17]; memcpy(segname, base + so - 16, 16); segname[16] = 0;
                if (strcmp(sect, "__stubs") == 0) {
                    memcpy(&g_stubsAddr, base + so + 32, 8);
                    memcpy(&g_stubsSize, base + so + 40, 8);
                    memcpy(&g_stubsRes1, base + so + 68, 4);  // reserved1(68), +64 是 flags
                    g_hasStubs = YES;
                }
                // __got / __auth_got: 数据指针类符号(SQAAMc 等)
                if ((strcmp(sect, "__got") == 0 || strcmp(sect, "__auth_got") == 0) && g_gotCount < MF_MAX_GOT) {
                    memcpy(&g_gotAddr[g_gotCount], base + so + 32, 8);
                    memcpy(&g_gotSize[g_gotCount], base + so + 40, 8);
                    memcpy(&g_gotRes1[g_gotCount], base + so + 68, 4);
                    g_gotCount++;
                }
                so += 80;
            }
        } else if (cmd == LC_SYMTAB) {
            memcpy(&g_symoff, base + off + 8, 4);
            memcpy(&g_nsyms,  base + off + 12, 4);
            memcpy(&g_stroff, base + off + 16, 4);
            g_hasSymtab = YES;
        } else if (cmd == LC_DYSYMTAB) {
            memcpy(&g_indirectoff, base + off + 8 + 12 * 4, 4);
            memcpy(&g_nindirect,   base + off + 8 + 13 * 4, 4);
            g_hasIndirect = YES;
        }
        off += cs;
    }
}

// 间接符号表按名字找 stub → 解码 adrp/ldr → GOT 槽运行时地址
static void *mfFindSlotForSymbol(const char *target) {
    if (!g_hasStubs || !g_hasSymtab || !g_hasIndirect || !g_nindirect || !g_stubsSize) return NULL;
    uint64_t stubCount = g_stubsSize / 12;
    for (uint64_t j = 0; j < stubCount; j++) {
        uint64_t iidx = (uint64_t)g_stubsRes1 + j;
        if (iidx >= g_nindirect) break;
        uint32_t *ip = (uint32_t *)mfFileOffToPtr(g_indirectoff + iidx * 4);
        if (!ip) continue;
        uint32_t symIdx = *ip;
        if (symIdx == 0xFFFFFFFF || symIdx >= g_nsyms) continue;
        uint32_t n_strx = *(uint32_t *)mfFileOffToPtr(g_symoff + (uint64_t)symIdx * 16);
        const char *name = (const char *)mfFileOffToPtr(g_stroff + n_strx);
        if (!name || strcmp(name, target) != 0) continue;
        uint64_t stubVm = g_slide + g_stubsAddr + j * 12;
        uint32_t adrp = *(uint32_t *)stubVm;
        uint32_t ldr  = *(uint32_t *)(stubVm + 4);
        if ((adrp & 0x9F00001F) != 0x90000010) continue;   // adrp x16
        if ((ldr  & 0xFFC003FF) != 0xF9400210) continue;   // ldr x16,[x16,#imm]
        int64_t immhi = ((int64_t)(adrp >> 5) & 0x7FFFF) << 2;
        int64_t immlo = (adrp >> 29) & 3;
        uint64_t page = (stubVm & ~0xFFFULL) + ((immhi | immlo) << 12);
        uint64_t slot = page + (uint64_t)((ldr >> 10) & 0xFFF) * 8;
        return (void *)slot;
    }
    return NULL;
}

// __got 槽查找(数据指针类: SQAAMc / VMa / VMn)
static void *mfFindGotSlotForSymbol(const char *target) {
    if (!g_hasSymtab || !g_hasIndirect || !g_nindirect) return NULL;
    for (int g = 0; g < g_gotCount; g++) {
        uint64_t count = g_gotSize[g] / 8;
        for (uint64_t j = 0; j < count; j++) {
            uint64_t iidx = (uint64_t)g_gotRes1[g] + j;
            if (iidx >= g_nindirect) break;
            uint32_t *ip = (uint32_t *)mfFileOffToPtr(g_indirectoff + iidx * 4);
            if (!ip) continue;
            uint32_t symIdx = *ip;
            if (symIdx == 0xFFFFFFFF || symIdx >= g_nsyms) continue;
            uint32_t n_strx = *(uint32_t *)mfFileOffToPtr(g_symoff + (uint64_t)symIdx * 16);
            const char *name = (const char *)mfFileOffToPtr(g_stroff + n_strx);
            if (!name || strcmp(name, target) != 0) continue;
            return (void *)(g_slide + g_gotAddr[g] + j * 8);
        }
    }
    return NULL;
}

static void mfPatchSlotNamed(void *slot, void *impl, const char *name) {
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    uint64_t page = (uint64_t)slot & ~(uint64_t)(ps - 1);
    if (mprotect((void *)page, ps, PROT_READ | PROT_WRITE) != 0) {
        mfCompatDiag(@"fail", [NSString stringWithFormat:@"mprotect %s errno=%d", name, errno]);
        return;
    }
    *(void **)slot = impl;
    mprotect((void *)page, ps, PROT_READ);
    mfCompatLog("GOT patched: %s slot=%p -> %p", name, slot, impl);
}

static void mfPatchSlot(void *slot, void *impl, int tag) {
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    uint64_t page = (uint64_t)slot & ~(uint64_t)(ps - 1);
    if (mprotect((void *)page, ps, PROT_READ | PROT_WRITE) != 0) {
        mfCompatDiag(@"fail", [NSString stringWithFormat:@"mprotect t=%d errno=%d", tag, errno]);
        return;
    }
    *(void **)slot = impl;
    mprotect((void *)page, ps, PROT_READ);
    mfCompatLog("GOT patched: %s slot=%p -> %p", kTgt[tag], slot, impl);
}

static void mfCompatPatchMainBinary(void) {
    if (!mfFindMainImage()) {
        mfCompatDiag(@"fail", @"main image not found");
        return;
    }
    mfCompatDiag(@"step_img", [NSString stringWithFormat:@"idx=%u slide=%p ncmds=%u", g_imgIndex, (void *)g_slide, g_mh->ncmds]);
    mfParseLcs();
    mfCompatDiag(@"step_lcs", [NSString stringWithFormat:@"segs=%d stubs=%d/%#llx res1=%u sym=%u indirect=%u",
                g_segCount, g_hasStubs, (unsigned long long)g_stubsSize, g_stubsRes1,
                g_hasSymtab ? g_nsyms : 0, g_hasIndirect ? g_nindirect : 0]);

    // 等价实现
    g_impl[0] = dlsym(RTLD_DEFAULT, "swift_getFunctionTypeMetadata");
    if (!g_impl[0]) g_impl[0] = dlsym(RTLD_DEFAULT, "_swift_getFunctionTypeMetadata");
    g_impl[1] = dlsym(RTLD_DEFAULT, "malloc");
    if (!g_impl[1]) g_impl[1] = dlsym(RTLD_DEFAULT, "_malloc");
    g_impl[2] = (void *)compat_isStackSafe;
    g_impl[3] = (void *)compat_deinitNoop;
    if (!g_impl[0] || !g_impl[1]) {
        mfCompatDiag(@"fail", [NSString stringWithFormat:@"dlsym null g0=%p g1=%p", g_impl[0], g_impl[1]]);
        return;
    }

    int patched = 0;
    for (int t = 0; t < 4; t++) {
        void *slot = mfFindSlotForSymbol(kTgt[t]);
        if (!slot) {
            mfCompatDiag(@"fail", [NSString stringWithFormat:@"stub not found: %s", kTgt[t]]);
            continue;
        }
        mfPatchSlot(slot, g_impl[t], t);
        patched++;
    }
    mfCompatDiag(@"done", [NSString stringWithFormat:@"patched=%d/4", patched]);

    // ---- Zora 类 app: iOS 26 SDK strong 缺符号 → 17.0 等价转发 ----
    static const char *kFwd[][2] = {
        // {app_symbol, ios17_equivalent}
        {"_$s8StoreKit11TransactionV5OfferV11PaymentModeV9freeTrialAGvgZ",
         "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeV9freeTrialAGvgZ"},
        {"_$s8StoreKit11TransactionV5OfferV11PaymentModeVMa",
         "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVMa"},
        {"_$s8StoreKit11TransactionV5OfferV11PaymentModeVMn",
         "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVMn"},
        {"_$s8StoreKit11TransactionV5OfferV11PaymentModeVSQAAMc",
         "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVSQAAMc"},
        {"_$s8StoreKit11TransactionV5OfferV11paymentModeAE07PaymentF0VSgvg",
         "_$s8StoreKit7ProductV17SubscriptionOfferV11paymentModeAE07PaymentG0Vvg"},
        {"_$s8StoreKit11TransactionV5OfferVMa",
         "_$s8StoreKit7ProductV17SubscriptionOfferVMa"},
        {"_$s8StoreKit11TransactionV5OfferVMn",
         "_$s8StoreKit7ProductV17SubscriptionOfferVMn"},
        {"_$s8StoreKit11TransactionV5offerAC5OfferVSgvg",
         "_$s8StoreKit7ProductV18subscriptionOfferAC17SubscriptionOfferVSgvg"},
        {"_$s7SwiftUI11WindowGroupV2id5title11lazyContentACyxGSSSg_AA4TextVSgxyctcfC",
         "_$s7SwiftUI11WindowGroupV2id7contentACyxGSS_xyXEtcfC"},
    };
    int nfwd = sizeof(kFwd)/sizeof(kFwd[0]);
    int fwPatched = 0;
    for (int f = 0; f < nfwd; f++) {
        void *impl = dlsym(RTLD_DEFAULT, kFwd[f][1]);
        if (!impl) {
            // 无 17.0 等价 → 惰性 nil(仅当 app 实际调用才触发)
            impl = dlsym(RTLD_DEFAULT, "malloc"); // 保底非空, 调用者拿到垃圾但至少不 PC=0
        }
        if (!impl) continue;
        void *slot = mfFindSlotForSymbol(kFwd[f][0]);
        if (!slot) slot = mfFindGotSlotForSymbol(kFwd[f][0]);
        if (!slot) { mfCompatDiag(@"fwmiss", [NSString stringWithFormat:@"%s", kFwd[f][0]]); continue; }
        mfPatchSlotNamed(slot, impl, kFwd[f][0]);
        fwPatched++;
    }
    mfCompatDiag(@"fwdone", [NSString stringWithFormat:@"fwdPatched=%d/%d", fwPatched, nfwd]);
}

// ==================== v2.51 XRAY: 第三方修复样本观察机 ====================
// 标本: /var/jb/usr/lib/MinisFix/FixCrash.dylib (第三方混淆 dylib, ctor 驱动, 24 imports)
// 诊断模式(mfXray, probe 构建缺省 ON):
//   1. add_image 回调(dlopen 内部, bind 完成/initializer 未跑)布 GOT 蹦床 ×5
//      -> 其 ctor 全程在钩下, 解密后类名/selector/IMP 落 mfcompat.log
//   2. +3s 扫其 __DATA/__DATA_CONST 摘解密遗留 ASCII
//   3. +6s 全类方法表 diff: IMP∈标本镜像区间 = 它装的钩子
// 生产模式: 纯 dlopen, 标本自行工作
// 铁律: objc_msgSend 不钩(变参 ABI); 蹦床全部 passthrough; 标本缺席 = 全 no-op

#define MF_FC_PATH "/var/jb/usr/lib/MinisFix/FixCrash.dylib"
#define XRAY_MAX_LOG 300

typedef id (*mfGetClassT)(const char *);
typedef SEL (*mfSelRegT)(const char *);
typedef BOOL (*mfAddMethodT)(id, SEL, IMP, const char *);
typedef void *(*mfGetInstMethodT)(void *, void *);   // Method 返回值绝不声明 id: ARC 会插入 objc_retain 打死非对象指针
typedef IMP (*mfSetImpT)(Method, IMP);

static mfGetClassT o_getClass;
static mfSelRegT o_selReg;
static mfAddMethodT o_addMethod;
static mfGetInstMethodT o_getInstMethod;
static mfSetImpT o_setImp;

static const struct mach_header_64 *g_fcMH;
static intptr_t g_fcSlide;
static uintptr_t g_fcLo, g_fcHi;   // 标本镜像 slid 区间
static int g_xrayOn;
static int g_fcCnt[5];

// IMP 归属: 返回静态环缓冲描述(防单行双参别名)
static const char *mfImpWhere(uintptr_t imp) {
    static char ring[4][80];
    static int ri;
    char *buf = ring[ri++ & 3];
    if (!imp) { snprintf(buf, 80, "NULL"); return buf; }
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        // 该镜像 slid 覆盖区间
        uintptr_t base = (uintptr_t)h, hi = base;
        const uint8_t *b = (const uint8_t *)h;
        uint32_t off = sizeof(struct mach_header_64), nc = h->ncmds;
        for (uint32_t k = 0; k < nc && off + 80 < 0x8000; k++) {
            uint32_t cmd = *(uint32_t *)(b + off), cs = *(uint32_t *)(b + off + 4);
            if (cmd == LC_SEGMENT_64 && strncmp((const char *)(b + off + 8), "__PAGEZERO", 10) != 0) {
                uint64_t vm = *(uint64_t *)(b + off + 24), vs = *(uint64_t *)(b + off + 32);
                if (base + vm + vs > hi) hi = base + vm + vs;
            }
            off += cs;
        }
        if (imp >= base && imp < hi) {
            const char *p = _dyld_get_image_name(i);
            const char *leaf = p ? strrchr(p, '/') : NULL;
            if (g_fcMH && h == g_fcMH) snprintf(buf, 80, "FixCrash+%#lx", (unsigned long)(imp - base));
            else snprintf(buf, 80, "%s+%#lx", leaf ? leaf + 1 : "?", (unsigned long)(imp - base));
            return buf;
        }
    }
    snprintf(buf, 80, "heap/%#lx", (unsigned long)imp);
    return buf;
}

static id t_getClass(const char *name) {
    id r = o_getClass(name);
    if (g_fcCnt[0]++ < XRAY_MAX_LOG)
        mfCompatLog("[xray] getClass(%s) -> %s", name ?: "?", r ? object_getClassName(r) : "nil");
    return r;
}
static SEL t_selReg(const char *name) {
    SEL r = o_selReg(name);
    if (g_fcCnt[1]++ < XRAY_MAX_LOG)
        mfCompatLog("[xray] sel(%s)", name ?: "?");
    return r;
}
static BOOL t_addMethod(id cls, SEL sel, IMP imp, const char *types) {
    BOOL r = o_addMethod(cls, sel, imp, types);
    if (g_fcCnt[2]++ < XRAY_MAX_LOG)
        mfCompatLog("[xray] addMethod(%s, %s, imp=%s, enc=%s) -> %d",
                    cls ? object_getClassName(cls) : "nil",
                    sel ? sel_getName(sel) : "nil",
                    mfImpWhere((uintptr_t)imp), types ?: "?", r);
    return r;
}
static void *t_getInstMethod(void *cls, void *sel) {
    void *r = o_getInstMethod(cls, sel);
    if (g_fcCnt[3]++ < XRAY_MAX_LOG)
        mfCompatLog("[xray] getInstanceMethod(%s, %s) -> %s",
                    cls ? object_getClassName((__bridge id)cls) : "nil",
                    sel ? sel_getName((SEL)sel) : "nil",
                    r ? "HIT" : "miss");
    return r;
}
static IMP t_setImp(Method m, IMP imp) {
    IMP old = o_setImp(m, imp);
    SEL s = m ? method_getName(m) : NULL;
    if (g_fcCnt[4]++ < XRAY_MAX_LOG)
        mfCompatLog("[xray] *** SETIMP(%s, old=%s new=%s)",
                    s ? sel_getName(s) : "nil",
                    mfImpWhere((uintptr_t)old), mfImpWhere((uintptr_t)imp));
    return old;   // 必须原样返回旧 IMP
}

// 标本镜像区间(遍历 LC_SEGMENT_64)
static void mfFcRange(void) {
    g_fcLo = (uintptr_t)g_fcMH;
    g_fcHi = g_fcLo;
    const uint8_t *b = (const uint8_t *)g_fcMH;
    uint32_t off = sizeof(struct mach_header_64);
    for (uint32_t k = 0; k < g_fcMH->ncmds && off + 80 < 0x80000; k++) {
        uint32_t cmd = *(uint32_t *)(b + off), cs = *(uint32_t *)(b + off + 4);
        if (cmd == LC_SEGMENT_64 && strncmp((const char *)(b + off + 8), "__PAGEZERO", 10) != 0) {
            uint64_t vm = *(uint64_t *)(b + off + 24), vs = *(uint64_t *)(b + off + 32);
            if (g_fcSlide + vm + vs > g_fcHi) g_fcHi = g_fcSlide + vm + vs;
        }
        off += cs;
    }
    mfCompatLog("[xray] range %#lx..%#lx", (unsigned long)g_fcLo, (unsigned long)g_fcHi);
}

// add_image 回调: 名字核对 -> 换全局镜像状态 -> 布蹦床 -> 记区间
static void mfXrayAddImage(const struct mach_header *mh, intptr_t slide) {
    if (g_fcMH || !g_xrayOn) return;
    const struct mach_header_64 *m64 = (const struct mach_header_64 *)mh;
    if (!m64 || m64->magic != MH_MAGIC_64 || m64->filetype != MH_DYLIB) return;
    BOOL ours = NO;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        if ((const struct mach_header_64 *)_dyld_get_image_header(i) != m64) continue;
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "FixCrash.dylib")) ours = YES;
        break;
    }
    if (!ours) return;

    g_fcMH = m64; g_fcSlide = slide;
    mfCompatLog("[xray] sample mapped mh=%p slide=%p", m64, (void *)slide);

    const struct mach_header_64 *saveMH = g_mh; intptr_t saveSlide = g_slide;
    g_mh = m64; g_slide = slide;
    mfParseLcs();   // 全局查找状态指向标本

    struct { const char *name; void **orig; void *trap; } hooks[] = {
        {"_objc_getClass",             (void **)&o_getClass,       (void *)t_getClass},
        {"_sel_registerName",          (void **)&o_selReg,         (void *)t_selReg},
        {"_class_addMethod",           (void **)&o_addMethod,      (void *)t_addMethod},
        {"_class_getInstanceMethod",   (void **)&o_getInstMethod,  (void *)t_getInstMethod},
        {"_method_setImplementation",  (void **)&o_setImp,         (void *)t_setImp},
    };
    int ok = 0;
    for (int i = 0; i < 5; i++) {
        void *slot = mfFindSlotForSymbol(hooks[i].name);
        if (!slot) slot = mfFindGotSlotForSymbol(hooks[i].name);
        if (!slot) { mfCompatLog("[xray] MISS %s", hooks[i].name); continue; }
        *hooks[i].orig = *(void **)slot;    // bind 已完成, 槽内即原函数
        mfPatchSlotNamed(slot, hooks[i].trap, hooks[i].name);
        ok++;
    }
    mfCompatLog("[xray] hooks=%d/5", ok);
    mfFcRange();
    g_mh = saveMH; g_slide = saveSlide;   // 恢复主镜像状态
}

// L2: 标本 __DATA 区解密遗留 ASCII 摘果
static void mfXrayDumpData(void) {
    if (!g_fcMH) return;
    const uint8_t *b = (const uint8_t *)g_fcMH;
    uint32_t off = sizeof(struct mach_header_64);
    int emitted = 0;
    for (uint32_t k = 0; k < g_fcMH->ncmds && off + 80 < 0x80000 && emitted < 400; k++) {
        uint32_t cmd = *(uint32_t *)(b + off), cs = *(uint32_t *)(b + off + 4);
        if (cmd == LC_SEGMENT_64) {
            const char *sn = (const char *)(b + off + 8);
            uint64_t vm = *(uint64_t *)(b + off + 24), vs = *(uint64_t *)(b + off + 32);
            if (vs && vs <= 0x20000 && (strncmp(sn, "__DATA", 6) == 0)) {
                const uint8_t *p = (const uint8_t *)(g_fcSlide + vm);
                uint64_t run = 0;
                for (uint64_t i = 0; i <= vs && emitted < 400; i++) {
                    uint8_t c = i < vs ? p[i] : 0;
                    if (c >= 0x20 && c < 0x7f) { if (!run) run = i + 1; }
                    else {
                        if (run && i - (run - 1) >= 6) {
                            char tmp[120];
                            uint64_t len = i - (run - 1);
                            if (len > 110) len = 110;
                            memcpy(tmp, p + run - 1, len); tmp[len] = 0;
                            mfCompatLog("[xray] d %s+0x%llx '%s'", sn,
                                        (unsigned long long)(vm + run - 1), tmp);
                            emitted++;
                        }
                        run = 0;
                    }
                }
            }
        }
        off += cs;
    }
    mfCompatLog("[xray] dump done emitted=%d", emitted);
}

// L3: 全类方法表 diff, IMP∈标本区间 = 它装的钩子
static int mfXraySweepOne(Class c, BOOL meta) {
    unsigned cnt = 0;
    Method *ms = class_copyMethodList(c, &cnt);
    int hits = 0;
    for (unsigned j = 0; j < cnt; j++) {
        IMP imp = method_getImplementation(ms[j]);
        if ((uintptr_t)imp >= g_fcLo && (uintptr_t)imp < g_fcHi) {
            SEL s = method_getName(ms[j]);
            mfCompatLog("[xray] ** HOOK %c[%s %s] enc=%s imp=FixCrash+%#lx",
                        meta ? '+' : '-', object_getClassName(c),
                        s ? sel_getName(s) : "nil",
                        method_getTypeEncoding(ms[j]) ?: "?",
                        (unsigned long)((uintptr_t)imp - (g_fcSlide ? g_fcLo - g_fcSlide : 0)));
            hits++;
        }
    }
    if (ms) free(ms);
    return hits;
}
static void mfXraySweepMethods(void) {
    if (!g_fcMH || !g_fcLo) return;
    unsigned n = 0;
    Class *cl = objc_copyClassList(&n);
    int hits = 0;
    for (unsigned i = 0; i < n; i++) {
        hits += mfXraySweepOne(cl[i], NO);
        Class meta = object_getClass(cl[i]);
        if (meta && meta != cl[i]) hits += mfXraySweepOne(meta, YES);
    }
    if (cl) free(cl);
    mfCompatLog("[xray] sweep classes=%u hooks=%d", n, hits);
}

// 标本装载(dlopen 由我们掌控: 诊断模式先布钩再让 ctor 跑)
static void mfFixcrashStage(BOOL xray) {
    struct stat st;
    if (stat(MF_FC_PATH, &st) != 0) {
        mfCompatLog("[xray] sample absent %s", MF_FC_PATH);
        return;
    }
    g_xrayOn = xray;
    if (xray) _dyld_register_func_for_add_image(mfXrayAddImage);
    void *h = dlopen(MF_FC_PATH, RTLD_NOW);
    if (!h) {
        mfCompatLog("[xray] dlopen FAIL: %s", dlerror() ?: "?");
        return;
    }
    mfCompatLog("[xray] dlopen ok xray=%d", xray);
    if (xray) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3LL * NSEC_PER_SEC),
                       dispatch_get_global_queue(0, 0), ^{ @autoreleasepool { mfXrayDumpData(); } });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 6LL * NSEC_PER_SEC),
                       dispatch_get_global_queue(0, 0), ^{ @autoreleasepool { mfXraySweepMethods(); } });
    }
}

// ==================== v2.52 CK-SANITIZER: iOS17×新SDK CloudKit 兼容引擎 ====================
// 语义源: 2.51 Xray 全量还原第三方样本(见 [xray] 流), 干净复刻且通用化(不嵌 app 名):
//   1. setCloudKitContainerOptions: 非 nil 一律拦(容器退化纯本地), nil 放行走原 IMP
//   2. loadPersistentStores 包装: 载入前清扫各 description 云选项;
//      options 已含 NSPersistentStoreMirroring* 键 = 容器自管镜像 -> 不动(保守门)
//   3. 不碰 NSManagedObjectModel
// 门控: mfCompatAppList 含 bid; iOS>=18 自动跳过(云端路径无断言)
// 机理: iOS17.0 + iOS18+SDK 的 CloudKit store 加载断言(brk1)类崩溃, 云选项清空即活

static IMP g_ckOrigSetCK;
static IMP g_ckOrigLoad;

static void mfCKClearDesc(id desc) {
    @try {
        id opts = ((id (*)(id, SEL))objc_msgSend)(desc, sel_registerName("cloudKitContainerOptions"));
        if (opts) {
            ((void (*)(id, SEL, id))g_ckOrigSetCK)(desc, sel_registerName("setCloudKitContainerOptions:"), nil);
            mfCompatLog("[mfck] cleared pre-load url=%@",
                        ((id (*)(id, SEL))objc_msgSend)(desc, sel_registerName("URL")));
        }
    } @catch (NSException *e) {
        mfCompatLog("[mfck] clear desc exc: %@", e.name);
    }
}

static void mfCKInstall(void) {
    if (g_ckOrigSetCK) return;   // 幂等
    // iOS>=18 无此断言, 引擎静止
    NSOperatingSystemVersion v = [[NSProcessInfo processInfo] operatingSystemVersion];
    if (v.majorVersion >= 18) { mfCompatLog("[mfck] skip iOS %lld", (long long)v.majorVersion); return; }

    Class dc = objc_getClass("NSPersistentStoreDescription");
    Class cc = objc_getClass("NSPersistentContainer");
    if (!dc || !cc) { mfCompatLog("[mfck] classes absent"); return; }
    Method mCK = class_getInstanceMethod(dc, sel_registerName("setCloudKitContainerOptions:"));
    Method mL  = class_getInstanceMethod(cc, sel_registerName("loadPersistentStoresWithCompletionHandler:"));
    if (!mCK || !mL) { mfCompatLog("[mfck] methods absent"); return; }
    g_ckOrigSetCK = method_getImplementation(mCK);
    g_ckOrigLoad  = method_getImplementation(mL);

    // 1) setter: 非 nil 拦截
    IMP impCK = imp_implementationWithBlock(^(id self, id options) {
        if (options) {
            mfCompatLog("[mfck] blocked CK options assignment");
            return;
        }
        ((void (*)(id, SEL, id))g_ckOrigSetCK)(self, sel_registerName("setCloudKitContainerOptions:"), nil);
    });
    method_setImplementation(mCK, impCK);

    // 2) load 包装: 载入前清扫 -> 调原
    IMP impLoad = imp_implementationWithBlock(^(id self, id completion) {
        @try {
            id descs = ((id (*)(id, SEL))objc_msgSend)(self, sel_registerName("persistentStoreDescriptions"));
            for (id desc in descs) {
                id o = ((id (*)(id, SEL))objc_msgSend)(desc, sel_registerName("options"));
                id mir = o ? [o objectForKeyedSubscript:@"NSPersistentStoreMirroringOptionsKey"] : nil;
                if (!mir) mir = o ? [o objectForKeyedSubscript:@"NSPersistentStoreMirroringDelegateOptionKey"] : nil;
                if (mir) { mfCompatLog("[mfck] mirroring present, left unchanged"); continue; }
                mfCKClearDesc(desc);
            }
        } @catch (NSException *e) {
            mfCompatLog("[mfck] presweep exc: %@", e.name);
        }
        if (g_ckOrigLoad)
            ((void (*)(id, SEL, id))g_ckOrigLoad)(self, sel_registerName("loadPersistentStoresWithCompletionHandler:"), completion);
        else
            ((void (*)(id, SEL, id))objc_msgSend)(self, sel_registerName("loadPersistentStoresWithCompletionHandler:"), completion);
    });
    method_setImplementation(mL, impLoad);
    mfCompatLog("[mfck] engine installed");
}

// ---- 偏好: 是否需要修 ----
static BOOL mfCompatNeeded(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@MF_PREF_PATH] ?: @{};
    NSArray *list = d[@"mfCompatAppList"];
    if (![list isKindOfClass:[NSArray class]] || list.count == 0) return NO;
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (bid.length == 0) return NO;
    return [list containsObject:bid];
}

__attribute__((constructor)) static void CompatPatcherCtor(void) {
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        // 系统进程守卫(与 IAPtools 同律): 只服务用户 app
        if (bid.length == 0 || [bid.lowercaseString hasPrefix:@"com.apple."]) return;
        // v2.17.3: 非目标 app 直接走, 不写 diag(省一次 plist 全量重写, 写多必脏)
        BOOL needed = mfCompatNeeded();
        if (!needed) return;
        mfCompatDiag(@"ctor", [NSString stringWithFormat:@"pid=%d bid=%@", getpid(), bid ?: @"NIL"]);
        mfCompatDiag(@"needed", @"YES");
        mfCompatPatchMainBinary();
        // v2.51 probe: 标本装载 + 观察机(mfXray 缺省 ON, 显式 NO 关闭)
        NSDictionary *pf = [NSDictionary dictionaryWithContentsOfFile:@MF_PREF_PATH] ?: @{};
        BOOL xray = pf[@"mfXray"] ? [pf[@"mfXray"] boolValue] : YES;
        mfFixcrashStage(xray);
        mfCKInstall();   // v2.52: 通用 CK 兼容引擎(门控同 mfCompatAppList)
    }
}
