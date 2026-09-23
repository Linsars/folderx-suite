// MFProbe.m — 运行时状态观测模块(实验模拟页「运行时状态观测」开关控制, 默认关)
// 用途: 目标进程内某状态选择器(self=x20 swiftself)按需观测——命中开关且目标序言字节匹配时,
//   自建 inline hook 读取该实例的状态结构快照(纯读, malloc_size 越界守卫), 供离线比对。
// 门控双保险: ① 开关关(默认)→ 完全不 hook; ② 目标地址前 16 字节序言不匹配 → 拒绝 hook。
//   靠序言字节校验代替硬编码 bundleID, 无目标身份明文, 非匹配进程自动跳过(不碰宿主)。
// 机制: 自建 inline hook(vm_protect + 16B 跳转桩 + 搬 4 条位置无关 prologue → br target+0x10),
//   不依赖 ellekit/MSHookFunction(注入环境无该符号导出)。
// 偏移(运行时 = 主程序基址 + 静态 file_off; 值为该字段在实例内的字节偏移, 运行时元数据填):
//   sel off 0x27ccc70 · stateA 0x4727510 · stateB 0x4727508 · scope 0x4727518
//   flagA 0x4727428 · flagB 0x47274a0 · flagC 0x47274b0 · flagD 0x47274d0

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <libkern/OSCacheControl.h>
#import <malloc/malloc.h>
#import <dlfcn.h>

extern void mfLog(NSString *fmt, ...);

// —— 开关持久化(NSUserDefaults, 默认 NO = 不默认生效) ——
BOOL mfStateObsIsOn(void) {
    return [[NSUserDefaults standardUserDefaults] boolForKey:@"mfStateObsEnabled"];
}
void mfStateObsSetOn(BOOL on) {
    [[NSUserDefaults standardUserDefaults] setBool:on forKey:@"mfStateObsEnabled"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

// 主程序(MH_EXECUTE)运行时基址
static uintptr_t mfProbeMainBase(void) {
    uint32_t ic = _dyld_image_count();
    for (uint32_t i = 0; i < ic; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->filetype == MH_EXECUTE) return (uintptr_t)h;
    }
    return ic ? (uintptr_t)_dyld_get_image_header(0) : 0;
}

// 读偏移全局(存该字段在实例内的字节偏移, 运行时元数据 init 填)
//   越界守卫: fileoff 超出主程序映射跨度则返 0(防在体积不同的其他进程里越界)。
static uint64_t mfProbeImageSpan(uintptr_t base);   // 前置声明(定义在下方)
static uint64_t mfIvarOff(uintptr_t base, uintptr_t fileoff) {
    if (!base) return 0;
    uint64_t span = mfProbeImageSpan(base);
    if (span && fileoff + 8 > span) return 0;
    return *(uint64_t *)(base + fileoff);
}

// 主程序映射跨度(base..base+span): 走 load commands 取最大 vmaddr+vmsize 相对偏移。
//   用于越界守卫——目标偏移超出映射则拒读(防在体积不同的其他进程里越界 SIGSEGV)。
static uint64_t mfProbeImageSpan(uintptr_t base) {
    if (!base) return 0;
    const struct mach_header_64 *h = (const struct mach_header_64 *)base;
    if (h->magic != MH_MAGIC_64) return 0;
    const uint8_t *p = (const uint8_t *)(base + sizeof(struct mach_header_64));
    uint64_t maxend = 0, slide_ref = 0; BOOL have_ref = NO;
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const struct segment_command_64 *)p;
            if (!have_ref) { slide_ref = sc->vmaddr; have_ref = YES; }  // __TEXT vmaddr = 逻辑基址
            uint64_t rel = sc->vmaddr - slide_ref + sc->vmsize;
            if (rel > maxend) maxend = rel;
        }
        p += lc->cmdsize;
    }
    return maxend;
}

// dump n 字节十六进制(16/行), 只读
static void mfDumpHex(NSString *tag, uintptr_t addr, int n, uint64_t off) {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < n; i++) {
        if (i && i % 16 == 0) [s appendString:@"\n[stobs]          "];
        [s appendFormat:@"%02x ", *(uint8_t *)(addr + i)];
    }
    mfLog(@"[stobs]   %@ [+0x%llx, %dB]:\n[stobs]          %@", tag, off, n, s);
}

// self = x20(状态管理实例) → dump 有效状态结构快照
void mf_stObsLog(void *selfPtr) {
    static uint32_t cnt = 0;
    if (cnt >= 6) return;          // 高频选择器, 限量防刷屏
    cnt++;
    uintptr_t self = (uintptr_t)selfPtr;
    uintptr_t base = mfProbeMainBase();
    if (!self || !base) { mfLog(@"[stobs] self/base=0 跳过"); return; }

    size_t isz = malloc_size((void *)self);
    uint64_t offA    = mfIvarOff(base, 0x4727510);
    uint64_t offB    = mfIvarOff(base, 0x4727508);
    uint64_t offScope = mfIvarOff(base, 0x4727518);
    mfLog(@"[stobs] ===== 状态选择器触发 #%u self=%p instSize=%zu offA=0x%llx offB=0x%llx offScope=0x%llx =====",
          cnt, selfPtr, isz, offA, offB, offScope);

    // 选择器逻辑: A 首字节==1 用 A, 否则 B → 两份都 dump 便于对比
    if (offA && offA + 80 <= isz) mfDumpHex(@"stateA", self + offA, 80, offA);
    else mfLog(@"[stobs]   ⛔ A off 越界(0x%llx / size %zu)", offA, isz);
    if (offB && offB + 80 <= isz) mfDumpHex(@"stateB", self + offB, 80, offB);
    else mfLog(@"[stobs]   ⛔ B off 越界(0x%llx / size %zu)", offB, isz);
    if (offScope && offScope + 16 <= isz) mfDumpHex(@"scope(String)", self + offScope, 16, offScope);

    uint8_t ab = (offA && offA < isz) ? *(uint8_t *)(self + offA) : 0xFF;
    mfLog(@"[stobs]   → A 首字节=%d ⇒ 选择器%@", ab, ab == 1 ? @"用 A 分支" : @"用 B 分支");

    struct { const char *nm; uint64_t fo; } bf[] = {
        {"flagA", 0x4727428}, {"flagB", 0x47274a0},
        {"flagC", 0x47274b0}, {"flagD", 0x47274d0},
    };
    NSMutableString *bs = [NSMutableString string];
    for (int i = 0; i < 4; i++) {
        uint64_t o = mfIvarOff(base, bf[i].fo);
        if (o && o < isz) [bs appendFormat:@"%s=%d ", bf[i].nm, *(uint8_t *)(self + o)];
        else [bs appendFormat:@"%s=off?(0x%llx) ", bf[i].nm, o];
    }
    mfLog(@"[stobs]   flags: %@", bs);
}

// asm trampoline: 入口 x30=caller lr。保 x0-x8+lr → logger(x20) → 复原 →
//   执行被偷的 4 条 prologue(位置无关) → 跳 target+0x10。
extern void mf_stObsTramp(void);
void *g_mfStObsCont = NULL;   // = target + 0x10(运行时填)
__asm__(
  ".text\n"
  ".align 2\n"
  "_mf_stObsTramp:\n"
  "  stp x29, x30, [sp, #-16]!\n"       // 存 caller lr
  "  sub sp, sp, #80\n"
  "  stp x0, x1, [sp]\n"
  "  stp x2, x3, [sp, #16]\n"
  "  stp x4, x5, [sp, #32]\n"
  "  stp x6, x7, [sp, #48]\n"
  "  str x8, [sp, #64]\n"
  "  mov x0, x20\n"                      // swiftself → logger
  "  bl _mf_stObsLog\n"
  "  ldp x0, x1, [sp]\n"
  "  ldp x2, x3, [sp, #16]\n"
  "  ldp x4, x5, [sp, #32]\n"
  "  ldp x6, x7, [sp, #48]\n"
  "  ldr x8, [sp, #64]\n"
  "  add sp, sp, #80\n"
  "  ldp x29, x30, [sp], #16\n"         // 复原 caller lr → x30
  // 被偷的 4 条(位置无关): sub sp,#0x130 / stp d9,d8 / stp x28,x27 / stp x26,x25
  "  sub sp, sp, #0x130\n"
  "  stp d9, d8, [sp, #0xc0]\n"
  "  stp x28, x27, [sp, #0xd0]\n"
  "  stp x26, x25, [sp, #0xe0]\n"
  // 跳 target+0x10(续跳指令[4]):
  "  adrp x16, _g_mfStObsCont@PAGE\n"
  "  ldr x16, [x16, _g_mfStObsCont@PAGEOFF]\n"
  "  br x16\n"
);

// 自建 inline hook: vm_protect RW → 写 16B 跳转桩(ldr x16,[pc,#8];br x16;.quad tramp) → RX + icache
static BOOL mfProbePatch16(uintptr_t target, const uint8_t *newBytes, NSString **err) {
    uintptr_t pg = target & ~0x3FFFULL;
    size_t span = (target + 16 - pg + 0x3FFF) & ~0x3FFFULL;
    kern_return_t kr = vm_protect(mach_task_self(), pg, span, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { if (err) *err = [NSString stringWithFormat:@"vm_protect RW kr=%d", kr]; return NO; }
    memcpy((void *)target, newBytes, 16);
    kr = vm_protect(mach_task_self(), pg, span, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) { if (err) *err = [NSString stringWithFormat:@"vm_protect RX kr=%d", kr]; return NO; }
    sys_icache_invalidate((void *)target, 16);
    return YES;
}

// 安装: 开关开时, 目标地址序言字节匹配才 inline hook(双门控, 无 bundleID 明文)
void mfProbeInstall(void) {
    static BOOL done = NO;
    if (done) return;
    if (!mfStateObsIsOn()) return;                 // 开关门控(默认关): 静默跳过
    uintptr_t base = mfProbeMainBase();
    if (!base) return;
    uintptr_t target = base + 0x27ccc70;

    // 序言字节校验(前 4 条): 不匹配 = 非目标进程/地址漂移 → 拒绝 hook(唯一目标门控)
    static const uint8_t want[16] = {
        0xff,0xc3,0x04,0xd1, 0xe9,0x23,0x0c,0x6d, 0xfc,0x6f,0x0d,0xa9, 0xfa,0x67,0x0e,0xa9 };
    if (memcmp((void *)target, want, 16) != 0) return;   // 静默跳过, 不 log(避免非目标进程刷日志)

    g_mfStObsCont = (void *)(target + 0x10);

    uint8_t stub[16];
    uint32_t ldr = 0x58000050, br = 0xd61f0200;
    uint64_t tramp = (uint64_t)(uintptr_t)mf_stObsTramp;
    memcpy(stub, &ldr, 4); memcpy(stub + 4, &br, 4); memcpy(stub + 8, &tramp, 8);

    NSString *err = nil;
    if (mfProbePatch16(target, stub, &err)) {
        done = YES;
        mfLog(@"[stobs] ✅ inline hook 状态选择器 @ %p → tramp %p — 触发功能区看 [stobs] dump", (void *)target, (void *)tramp);
    } else {
        mfLog(@"[stobs] ⛔ inline hook 失败: %@", err);
    }
}
