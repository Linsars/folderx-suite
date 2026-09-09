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
#import <mach/mach_time.h>
#import <mach/mach.h>   // boolean_t / mach_msg_header_t(授权应答器类型)
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
static void mfXrayLog(const char *fmt, ...) {
    // v2.53.4: 关键事件单独落盘(永不轮转)——sel 洪水不再冲掉装载/授权行
    @autoreleasepool {
        va_list ap; va_start(ap, fmt);
        char buf[512]; vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
        NSString *home = NSHomeDirectory();
        if (!home) { va_end(ap); return; }
        uint64_t now = mach_absolute_time();
        mach_timebase_info_data_t tb; mach_timebase_info(&tb);
        FILE *f = fopen([[home stringByAppendingPathComponent:@"Documents/mfcompat_xray.log"] UTF8String], "a");
        if (f) { fprintf(f, "[%lluns] %s\n", (unsigned long long)(now * tb.numer / tb.denom / 1000), buf); fclose(f); }
        va_end(ap);
    }
}

static void mfCompatLog(const char *fmt, ...) {
    @autoreleasepool {
        va_list ap; va_start(ap, fmt);
        char buf[512]; vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
        NSString *home = NSHomeDirectory();
        if (!home) return;
        NSString *path = [home stringByAppendingPathComponent:@"Documents/mfcompat.log"];
        // v2.53.2: 轮转(>64KB 截掉前半保留尾部) + 每行带 us 时间戳(解密循环节奏分析)
        NSDictionary *at = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
        if (at && [at fileSize] > 65536) {
            NSData *data = [NSData dataWithContentsOfFile:path];
            if (data.length > 32768) {
                NSData *tail = [data subdataWithRange:NSMakeRange(data.length - 32768, 32768)];
                NSString *t = [[NSString alloc] initWithData:tail encoding:NSUTF8StringEncoding] ?: @"";
                NSRange nl = [t rangeOfString:@"\n"];
                if (nl.location != NSNotFound && nl.location + 1 < t.length)
                    t = [t substringFromIndex:nl.location + 1];
                [t writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
            }
        }
        static uint64_t base = 0;
        uint64_t now = mach_absolute_time();
        if (!base) base = now;
        mach_timebase_info_data_t tb; mach_timebase_info(&tb);
        uint64_t us = (now - base) * tb.numer / tb.denom / 1000;
        FILE *f = fopen(path.UTF8String, "a");
        if (f) { fprintf(f, "[%lluus] %s\n", (unsigned long long)us, buf); fclose(f); }
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

#define MF_FC_PATH "/var/jb/usr/lib/MinisFix/Sample.dylib"
#define XRAY_MAX_LOG 2000

typedef id (*mfGetClassT)(const char *);
typedef SEL (*mfSelRegT)(const char *);
typedef BOOL (*mfAddMethodT)(id, SEL, IMP, const char *);
typedef void *(*mfGetInstMethodT)(void *, void *);   // Method 返回值绝不声明 id: ARC 会插入 objc_retain 打死非对象指针
typedef IMP (*mfSetImpT)(Method, IMP);
// v2.53: 标本通用化扩展(Reflix 授权体系同款符号)
typedef void *(*mfDlsymT)(void *, const char *);
typedef int (*mfVmProtectT)(void *, unsigned long, unsigned long, int, int);
typedef int (*mfSysctlT)(const char *, void *, unsigned long *, void *, unsigned long);
typedef int (*mfMachServerT)(void *, unsigned int, unsigned int, unsigned int);
typedef int (*mfPthreadCreateT)(void *, const void *, void *(*)(void *), void *);

static mfGetClassT o_getClass;
static mfSelRegT o_selReg;
static mfAddMethodT o_addMethod;
static mfGetInstMethodT o_getInstMethod;
static mfSetImpT o_setImp;
static mfDlsymT o_dlsym;
static mfVmProtectT o_vmProtect;
static mfSysctlT o_sysctl;
static mfMachServerT o_machServer;
static mfPthreadCreateT o_pthreadCreate;

static const struct mach_header_64 *g_fcMH;
static intptr_t g_fcSlide;
static uintptr_t g_fcLo, g_fcHi;   // 标本镜像 slid 区间
static int g_xrayOn;
static int g_fcCnt[10];

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
    int c = g_fcCnt[0]++;
    if (c == 0 || (c > 0 && c % 250 == 0) || c == XRAY_MAX_LOG - 1)
        mfCompatLog("[xray] getClass(%s) -> %s #%d", name ?: "?", r ? object_getClassName(r) : "nil", c);
    return r;
}
static SEL t_selReg(const char *name) {
    SEL r = o_selReg(name);
    // v2.53.4: 固定节拍(首/每 250/尾)——按名限频在 5-sel 轮换循环下失效(每次调用都算换名)
    int c = g_fcCnt[1]++;
    if (c == 0 || (c > 0 && c % 250 == 0) || c == XRAY_MAX_LOG - 1)
        mfCompatLog("[xray] sel(%s) #%d", name ?: "?", c);
    return r;
}
static BOOL t_addMethod(id cls, SEL sel, IMP imp, const char *types) {
    BOOL r = o_addMethod(cls, sel, imp, types);
    if (g_fcCnt[2]++ < XRAY_MAX_LOG)
        mfXrayLog("[xray] addMethod(%s, %s, imp=%s, enc=%s) -> %d",
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
        mfXrayLog("[xray] *** SETIMP(%s, old=%s new=%s)",
                    s ? sel_getName(s) : "nil",
                    mfImpWhere((uintptr_t)old), mfImpWhere((uintptr_t)imp));
    return old;   // 必须原样返回旧 IMP
}
// v2.53 授权体系蹦床: 只记参, 尾调原函数
static void *t_dlsym(void *h, const char *name) {
    void *r = o_dlsym(h, name);
    if (g_fcCnt[5]++ < XRAY_MAX_LOG)
        mfXrayLog("[xray] dlsym(handle=%p %s) -> %s", h, name ?: "?", mfImpWhere((uintptr_t)r));
    return r;
}
static int t_vmProtect(void *t, unsigned long len, unsigned long maxp, int curp, int newp) {
    int r = o_vmProtect(t, len, maxp, curp, newp);
    if (g_fcCnt[6]++ < XRAY_MAX_LOG)
        mfXrayLog("[xray] *** VMPROTECT t=%p len=%#lx cur=%d new=%d kr=%d",
                    t, len, curp, newp, r);
    return r;
}
static int t_sysctl(const char *name, void *oldp, unsigned long *oldlenp, void *newp, unsigned long newlen) {
    int r = o_sysctl(name, oldp, oldlenp, newp, newlen);
    if (g_fcCnt[7]++ < XRAY_MAX_LOG)
        mfXrayLog("[xray] sysctlbyname(%s) kr=%d", name ?: "?", r);
    return r;
}
// v2.55.5: mach 许可服务器授权应答器 demux(和 Xray 蹦床同一个布点, 已验证 7/10 生效)
//   MIG 协议透明赌注: 全 0 响应 = KERN_SUCCESS = "授权通过" (不依赖具体消息布局)
static boolean_t mfMachAuthDemux(mach_msg_header_t *in, mach_msg_header_t *out) {
    if (!out) return FALSE;
    memset(out, 0, sizeof(mach_msg_header_t));
    out->msgh_bits = MACH_MSG_TYPE_MAKE_SEND;
    out->msgh_remote_port = in ? in->msgh_remote_port : MACH_PORT_NULL;
    out->msgh_local_port = MACH_PORT_NULL;
    out->msgh_size = sizeof(mach_msg_header_t);
    return TRUE;   // TRUE = mach_msg_server 把 out 作为应答发回 → 授权通过
}

// ★v2.55.5: t_machServer 双模式——记录(观察) + 应答(实验模拟 mach 应答器)。
//   布点不变(Xray GOT 蹦床, 标本 dlopen 时 mfXrayAddImage 布, 已验证 mach=1 命中),
//   只是行为升级: mfMachRespEnabled=ON 时换 demux 为"永远授权"。
//   fishhook rebind 已证伪(混淆大师 dlsym 动态解析 mach_msg_server, 静态 GOT 无引用
//   → rebind 0); Xray 手工 Mach-O 解析布 GOT 槽是唯一可靠的 hook 点。
static int t_machServer(void *demux, unsigned int maxsz, unsigned int timeout, unsigned int subsys) {
    if (g_fcCnt[8]++ < XRAY_MAX_LOG)
        mfXrayLog("[xray] *** MACH_MSG_SERVER demux=%s maxsz=%u timeout=%u subsys=%u —— 许可服务器上线",
                    mfImpWhere((uintptr_t)demux), maxsz, timeout, subsys);
    // 实验模拟 mach 应答器: 换 demux 永远授权(与观察模块解耦, 纯开关控)
    NSDictionary *pf = [NSDictionary dictionaryWithContentsOfFile:@MF_PREF_PATH] ?: @{};
    if ([pf[@"mfMachRespEnabled"] boolValue]) {
        mfXrayLog("[xray] MACH-RESP demux=%s -> AUTHORIZE (应答器 ON, maxsz=%u)",
                  mfImpWhere((uintptr_t)demux), maxsz);
        return o_machServer((void *)mfMachAuthDemux, maxsz, timeout, subsys);
    }
    return o_machServer(demux, maxsz, timeout, subsys);
}
static int t_pthreadCreate(void *t, const void *attr, void *(*fn)(void *), void *arg) {
    if (g_fcCnt[9]++ < XRAY_MAX_LOG)
        mfXrayLog("[xray] pthread_create fn=%s arg=%p", mfImpWhere((uintptr_t)fn), arg);
    return o_pthreadCreate(t, attr, fn, arg);
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
    mfXrayLog("[xray] range %#lx..%#lx", (unsigned long)g_fcLo, (unsigned long)g_fcHi);
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
        // v2.55.2: 标本路径匹配通用化——观察目录内任意 dylib 都算(不再硬编码旧路径/文件名)。
        //   旧判断只认 FixCrash.dylib / ScriptingPass.dylib / "MinisFix/" 段,
        //   而 v2.55 后标本在 /var/jb/var/mobile/minisfix/ 下(路径 minisfix/ 无 MinisFix/ 大写段) → 匹配失败。
        if (nm && (strstr(nm, "FixCrash.dylib") || strstr(nm, "ScriptingPass.dylib")
                   || strstr(nm, "minisfix/") || strstr(nm, "MinisFix/") || strstr(nm, "minisfix"))) ours = YES;
        break;
    }
    if (!ours) return;

    g_fcMH = m64; g_fcSlide = slide;
    mfXrayLog("[xray] sample mapped mh=%p slide=%p", m64, (void *)slide);

    const struct mach_header_64 *saveMH = g_mh; intptr_t saveSlide = g_slide;
    g_mh = m64; g_slide = slide;
    mfParseLcs();   // 全局查找状态指向标本

    struct { const char *name; void **orig; void *trap; } hooks[] = {
        {"_objc_getClass",             (void **)&o_getClass,       (void *)t_getClass},
        {"_sel_registerName",          (void **)&o_selReg,         (void *)t_selReg},
        {"_class_addMethod",           (void **)&o_addMethod,      (void *)t_addMethod},
        {"_class_getInstanceMethod",   (void **)&o_getInstMethod,  (void *)t_getInstMethod},
        {"_method_setImplementation",  (void **)&o_setImp,         (void *)t_setImp},
        // v2.53: 授权体系观测(Reflix 同款架构——mach 服务器/补丁/指纹/拉件)
        {"_dlsym",                     (void **)&o_dlsym,          (void *)t_dlsym},
        {"_vm_protect",                (void **)&o_vmProtect,      (void *)t_vmProtect},
        {"_sysctlbyname",              (void **)&o_sysctl,         (void *)t_sysctl},
        {"_mach_msg_server",           (void **)&o_machServer,     (void *)t_machServer},
        {"_pthread_create",            (void **)&o_pthreadCreate,  (void *)t_pthreadCreate},
    };
    int ok = 0;
    int nh = (int)(sizeof(hooks) / sizeof(hooks[0]));   // v2.53.3: 全表遍历——修 2.53.0/2 的 i<5 截断(后 5 个蹦床从未安装, VMPROTECT/MACH 全零的真凶)
    for (int i = 0; i < nh; i++) {
        void *slot = mfFindSlotForSymbol(hooks[i].name);
        if (!slot) slot = mfFindGotSlotForSymbol(hooks[i].name);
        if (!slot) { mfXrayLog("[xray] MISS %s", hooks[i].name); continue; }
        *hooks[i].orig = *(void **)slot;    // bind 已完成, 槽内即原函数
        mfPatchSlotNamed(slot, hooks[i].trap, hooks[i].name);
        ok++;
    }
    mfXrayLog("[xray] hooks=%d/%d", ok, nh);
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
    mfXrayLog("[xray] dump done emitted=%d", emitted);
}

// L3: 全类方法表 diff, IMP∈标本区间 = 它装的钩子
static void mfXraySweepMethods(void) {
    if (!g_fcMH || !g_fcLo) return;
    // v2.53.1: 纯名字比对模式——objc_getClass(逐个 realize) 在 iOS26-SDK Swift app
    // 上会撞泛型 conformance 空指针(Real Crash 2026-09-06 #3)。L3 改为只枚举类名
    // 不碰类对象: hook 目标靠标本 ctor 阶段的 addMethod/SETIMP 蹦床日志直接拿,
    // L3 降级为"标本镜像内 IMP 扫描+类名清单"快照, 不再触发任何 realize。
    NSString *exe = [[NSBundle mainBundle] executablePath] ?: @"";
    int clsTotal = 0;
    NSMutableString *list = [NSMutableString string];
    uint32_t ic = _dyld_image_count();
    for (uint32_t i = 0; i < ic; i++) {
        const char *img = _dyld_get_image_name(i);
        if (!img) continue;
        if (exe.length && strcmp(img, exe.fileSystemRepresentation) == 0) continue;
        unsigned cn = 0;
        char **names = objc_copyClassNamesForImage(img, &cn);
        clsTotal += cn;
        if (cn && list.length < 60000) {
            [list appendFormat:@"-- %s (%u)\n", [(@(img)) lastPathComponent].UTF8String ?: "?", cn];
            for (unsigned j = 0; j < cn && list.length < 60000; j++)
                [list appendFormat:@"%s\n", names[j]];
        }
        if (names) free(names);
    }
    // 落盘类名清单(诊断用, 不 realize)
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0]
                        stringByAppendingPathComponent:@"classdump"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *path = [dir stringByAppendingPathComponent:@"xray_classnames.txt"];
    [list writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    mfXrayLog("[xray] sweep names=%d -> %@ (no-realize mode)", clsTotal, path);
    // v2.53.4: 会话总结(自证钩子状态, 防日志轮转丢证据)
    mfXrayLog("[xray] SUMMARY cnt: getClass=%d sel=%d addM=%d getM=%d setI=%d dlsym=%d vmprot=%d sysctl=%d mach=%d pth=%d",
              g_fcCnt[0], g_fcCnt[1], g_fcCnt[2], g_fcCnt[3], g_fcCnt[4],
              g_fcCnt[5], g_fcCnt[6], g_fcCnt[7], g_fcCnt[8], g_fcCnt[9]);
}

// ---- 观察模块门控(v2.55: 独立于兼容列表, 不再绑架 mfCompatAppList) ----
// 三层门控, 任一层不过即 return(零损耗):
//   mfObserveEnabled  = 模块总开关(默认 OFF) —— OFF=完全静止, 不 dlopen/不注册 add_image/零日志
//   mfObserveAppList  = 观察列表(哪些 app 装标本)
//   mfObserveSelect   = 标本清单(含"不装载任何"选项, 默认不装载=无标本不观察)
// 与兼容列表彻底解耦: 兼容列表只管兼容补丁, 标本装载只看观察模块三开关。
static BOOL mfObserveNeeded(NSString *bid) {
    if (bid.length == 0) return NO;
    NSDictionary *pf = [NSDictionary dictionaryWithContentsOfFile:@MF_PREF_PATH] ?: @{};
    // 总开关: OFF=完全静止(即使观察列表/标本清单都选好也不跑, 零损耗调试后止损)
    if (![pf[@"mfObserveEnabled"] boolValue]) return NO;
    // 观察列表: 不在列表的 app 不观察
    NSArray *apps = pf[@"mfObserveAppList"];
    if (![apps isKindOfClass:[NSArray class]] || apps.count == 0) return NO;
    if (![apps containsObject:bid]) return NO;
    // 标本清单: 没有任何 mfObserve_* 开关开着 = "不装载任何" → 无标本可观察, 直接 return
    NSArray *all = [pf allKeys];
    BOOL anySel = NO;
    for (NSString *k in all) {
        if ([k hasPrefix:@"mfObserve_"] && [pf[k] boolValue]) { anySel = YES; break; }
    }
    if (!anySel) return NO;
    return YES;
}

// 标本装载(dlopen 由我们掌控: 诊断模式先布钩再让 ctor 跑)
static void mfFixcrashStage(BOOL xray, BOOL observeOn) {
    // 观察门控: 不满足三层门控直接 return, 不 dlopen/不注册 add_image/零日志
    if (!observeOn) return;
    // ★v2.55.1: 标本装载目录用 /var/jb/var/mobile/minisfix —— 关键修正:
    //   /var/mobile/minisfix 在沙盒 app 里读不到(沙盒挡 /var/mobile/);
    //   /var/jb/ 是注入器放宽的路径(老代码读 /var/jb/usr/lib 已证明沙盒可读),
    //   且 /var/jb/var/mobile/minisfix 属 mobile 拥有(设置页可写) → 两全。
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = @"/var/jb/var/mobile/minisfix";
    // v2.55: 目录可配(mfObserveDir), 默认 /var/jb/var/mobile/minisfix
    NSDictionary *pf = [NSDictionary dictionaryWithContentsOfFile:@MF_PREF_PATH] ?: @{};
    NSString *cfg = pf[@"mfObserveDir"];
    if ([cfg isKindOfClass:[NSString class]] && cfg.length > 0) dir = cfg;
    // 标本清单过滤: mfObserve_<文件名> = YES 才装(方案 B 多选清单, 每个 dylib 一个开关)
    NSArray *files = [fm contentsOfDirectoryAtPath:dir error:nil] ?: @[];
    BOOL any = NO;
    for (NSString *f in [files sortedArrayUsingSelector:@selector(compare)]) {
        if (![f.pathExtension isEqualToString:@"dylib"]) continue;
        // 不装载任何: 该 dylib 没被勾选(mfObserve_<名> != YES) → skip
        NSString *key = [@"mfObserve_" stringByAppendingString:f];
        if (![pf[key] boolValue]) continue;   // 未勾选 = 不装载这个
        any = YES;
        NSString *full = [dir stringByAppendingPathComponent:f];
        g_xrayOn = xray;
        if (xray) _dyld_register_func_for_add_image(mfXrayAddImage);
        void *h = dlopen(full.fileSystemRepresentation, RTLD_NOW);
        if (!h) { mfXrayLog("[xray] dlopen FAIL %s: %s", f.UTF8String, dlerror() ?: "?"); continue; }
        mfXrayLog("[xray] dlopen ok %s xray=%d", f.UTF8String, xray);
        if (xray) {
            const void *mh = (const void *)g_fcMH;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3LL * NSEC_PER_SEC),
                           dispatch_get_global_queue(0, 0), ^{ @autoreleasepool { mfXrayDumpData(); } });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 6LL * NSEC_PER_SEC),
                           dispatch_get_global_queue(0, 0), ^{ @autoreleasepool { mfXraySweepMethods(); } });
            (void)mh;
        }
    }
    if (!any) mfXrayLog("[xray] no selected sample (dir=%s)", dir.UTF8String);
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
static BOOL mfCompatNeededRaw(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@MF_PREF_PATH] ?: @{};
    NSArray *list = d[@"mfCompatAppList"];
    if (![list isKindOfClass:[NSArray class]] || list.count == 0) return NO;
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (bid.length == 0) return NO;
    return [list containsObject:bid];
}

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
        // v2.55: 观察模块门控独立于兼容列表——先判标本装载, 不写 diag(省 plist 全量重写)
        BOOL observeOn = mfObserveNeeded(bid);
        // v2.17.3: 非目标 app 直接走, 不写 diag(省一次 plist 全量重写, 写多必脏)
        BOOL needed = mfCompatNeeded();
        if (!needed && !observeOn) return;
        if (needed) {
            mfCompatDiag(@"ctor", [NSString stringWithFormat:@"pid=%d bid=%@", getpid(), bid ?: @"NIL"]);
            mfCompatDiag(@"needed", @"YES");
            mfCompatPatchMainBinary();
        }
        // v2.51 probe: 标本装载 + 观察机(mfXray 缺省 ON, 显式 NO 关闭)
        // v2.55: 标本装载独立观察模块门控(不再认兼容列表)——只在观察列表+选了标本+总开关开时跑
        if (observeOn) {
            NSDictionary *pf = [NSDictionary dictionaryWithContentsOfFile:@MF_PREF_PATH] ?: @{};
            BOOL xray = pf[@"mfXray"] ? [pf[@"mfXray"] boolValue] : YES;
            mfFixcrashStage(xray, YES);
        }
        if (needed) mfCKInstall();   // v2.52: 通用 CK 兼容引擎(门控同 mfCompatAppList)
    }
}
