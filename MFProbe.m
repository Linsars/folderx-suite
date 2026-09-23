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
#import <string.h>
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

// —— active 状态模板(源自目标函数内已存在的构造序列, 非凭空伪造) ——
//   80 字节结构字段: +0x00 disc · +0x08 周期(small) · +0x18 名称(large immortal)
//   +0x28 来源(small) · +0x38 double 有效期 · +0x40 状态(small)
static void mfBuildActiveTemplate(uint8_t *p, uintptr_t base) {
    memset(p, 0, 80);
    p[0x00] = 0x01;                                            // disc = active
    memcpy(p + 0x08, "monthly", 7);  p[0x17] = 0xE7;           // 周期 small string(count7)
    *(uint64_t *)(p + 0x18) = 0xD000000000000010ULL;           // 名称 countAndFlags(count16 immortal)
    *(uint64_t *)(p + 0x20) = ((uint64_t)(base + 0x3bb29a0)) | 0x8000000000000000ULL; // 名称 ptr → "pro_monthly_2026"(base+off, 运行时定位)
    memcpy(p + 0x28, "storekit", 8); p[0x37] = 0xE8;           // 来源 small string(count8)
    double exp = 4102444800.0;       memcpy(p + 0x38, &exp, 8); // 有效期(远未来, 防过期判定)
    memcpy(p + 0x40, "active", 6);   p[0x4f] = 0xE6;           // 状态 small string(count6)
}

// self = x20(状态管理实例) → 入口注入 active 模板, 令随后的选择器本体读到 active
void mf_stObsLog(void *selfPtr) {
    static uint32_t cnt = 0;
    uintptr_t self = (uintptr_t)selfPtr;
    uintptr_t base = mfProbeMainBase();
    if (!self || !base) return;

    size_t isz = malloc_size((void *)self);
    uint64_t offA = mfIvarOff(base, 0x4727510);   // 主状态 ivar(选择器首选: 首字节==1 时选它)
    uint64_t offB = mfIvarOff(base, 0x4727508);   // 次状态 ivar(选择器 fallback + 部分直读者)
    if (!offA || offA + 80 > isz) {                // 越界守卫: 非目标进程/漂移则不动
        if (cnt < 2) { cnt++; mfLog(@"[stobs] offA=0x%llx / size %zu 越界或未填, 跳过", offA, isz); }
        return;
    }
    // before 快照(限量) — 验证注入前是否 none
    if (cnt < 4) {
        cnt++;
        mfDumpHex(@"before(offA)", self + offA, 80, offA);
    }
    // 注入 active 模板到主/次状态 ivar(不限次, 覆盖 app 可能的 sync 回写):
    //   主状态首字节=1 → 选择器走该分支; 次状态同注 → 覆盖直读 serverProState 的消费点
    mfBuildActiveTemplate((uint8_t *)(self + offA), base);
    if (offB && offB + 80 <= isz) mfBuildActiveTemplate((uint8_t *)(self + offB), base);
    if (cnt <= 4) mfLog(@"[stobs] ✍️ 已注入 active 模板 @ offA=+0x%llx offB=+0x%llx (disc=1, plan=pro_monthly_2026)", offA, offB);
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
