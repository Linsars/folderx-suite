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

// ===================== hook_inject 通用注入执行器(数据驱动) =====================
//   配方 = 纯数据: hook 目标 + 序言校验 + ivar 偏移全局 + 结构字段填充表。
//   执行器 mfApplyRecipe 只认数据、零 app 专有逻辑 → 换靶子只换一条 recipe 数据。
//   (下一步: recipe 来源从内置常量改为持久层 / 侦查引擎产出的 JSON。)
typedef enum {
    MF_FLD_U8 = 0,     // 单字节
    MF_FLD_BYTES,      // 内联字节串(small string payload)
    MF_FLD_U64,        // 8 字节小端立即数
    MF_FLD_F64,        // double
    MF_FLD_IMMSTR,     // immortal String storage 指针 = (base + arg) | 0x8000000000000000
} MFFieldType;

typedef struct {
    uint32_t off;         // 结构内字节偏移
    MFFieldType type;
    uint64_t arg;         // U8/U64 值 或 IMMSTR 的常量 file_off
    double f64;           // F64 值
    const char *bytes;    // BYTES 数据
    uint32_t blen;        // BYTES 长度
} MFField;

typedef struct {
    const char *name;
    uint64_t sel_off;           // hook 目标(选择器)file_off
    const uint8_t *prologue;    // 16 字节序言校验(NULL=不校验)
    uint64_t ivar_globals[4];   // 存 ivar 偏移的全局 file_off(0 结尾)
    uint32_t struct_size;       // 注入结构大小
    const MFField *fields;
    int n_fields;
} MFInjectRecipe;

// 通用执行器: 按配方 fields 填充 struct buffer(base 供 IMMSTR 运行时定位)
static void mfApplyRecipe(uint8_t *p, const MFInjectRecipe *r, uintptr_t base) {
    memset(p, 0, r->struct_size);
    for (int i = 0; i < r->n_fields; i++) {
        const MFField *f = &r->fields[i];
        switch (f->type) {
            case MF_FLD_U8:     p[f->off] = (uint8_t)f->arg; break;
            case MF_FLD_BYTES:  memcpy(p + f->off, f->bytes, f->blen); break;
            case MF_FLD_U64:    *(uint64_t *)(p + f->off) = f->arg; break;
            case MF_FLD_F64:    memcpy(p + f->off, &f->f64, 8); break;
            case MF_FLD_IMMSTR: *(uint64_t *)(p + f->off) = ((uint64_t)(base + f->arg)) | 0x8000000000000000ULL; break;
        }
    }
}

// —— 内置配方(源自宿主 active 构造序列, 逐字段抄; 下一步由侦查引擎自动产出) ——
static const uint8_t kR0Prologue[16] = {
    0xff,0xc3,0x04,0xd1, 0xe9,0x23,0x0c,0x6d, 0xfc,0x6f,0x0d,0xa9, 0xfa,0x67,0x0e,0xa9 };
static const MFField kR0Fields[] = {
    {0x00, MF_FLD_U8,     .arg=0x01},                    // disc = active
    {0x08, MF_FLD_BYTES,  .bytes="lifetime", .blen=8},   // 周期 small string
    {0x17, MF_FLD_U8,     .arg=0xE8},                    //   small tag(count8)
    {0x18, MF_FLD_U64,    .arg=0xD00000000000000CULL},   // 名称 countAndFlags(count12 immortal)
    {0x20, MF_FLD_IMMSTR, .arg=0x3bb2800},               // 名称 ptr → 计划名常量前 12 字节
    {0x28, MF_FLD_BYTES,  .bytes="storekit", .blen=8},   // 来源 small string
    {0x37, MF_FLD_U8,     .arg=0xE8},
    {0x38, MF_FLD_F64,    .f64=4102444800000.0},         // 有效期(毫秒 since 1970 → 2100年)
    {0x40, MF_FLD_BYTES,  .bytes="active", .blen=6},     // 状态 small string
    {0x4f, MF_FLD_U8,     .arg=0xE6},
};
static const MFInjectRecipe kR0 = {
    .name = "r0",
    .sel_off = 0x27ccc70,
    .prologue = kR0Prologue,
    .ivar_globals = {0x4727510, 0x4727508, 0, 0},
    .struct_size = 80,
    .fields = kR0Fields,
    .n_fields = 10,
};

// 选中的活动配方(当前内置 kR0; 下一步可由持久层/侦查产出切换)
static const MFInjectRecipe *g_mfRecipe = &kR0;

// self = x20(状态管理实例) → 入口按配方注入, 令随后的选择器本体读到目标状态
void mf_stObsLog(void *selfPtr) {
    static uint32_t cnt = 0;
    uintptr_t self = (uintptr_t)selfPtr;
    uintptr_t base = mfProbeMainBase();
    if (!self || !base) return;
    const MFInjectRecipe *r = g_mfRecipe;
    if (!r) return;

    size_t isz = malloc_size((void *)self);
    // 遍历配方的 ivar 偏移全局, 逐个注入(越界守卫)
    int injected = 0, ntarget = 0;
    uint64_t offs[4] = {0};
    for (int i = 0; i < 4 && r->ivar_globals[i]; i++) {
        ntarget++;
        uint64_t off = mfIvarOff(base, r->ivar_globals[i]);
        offs[i] = off;
        if (!off || off + r->struct_size > isz) continue;   // 越界/未填 → 跳过该 ivar
        if (cnt < 4 && injected == 0) mfDumpHex(@"before", self + off, r->struct_size, off);
        mfApplyRecipe((uint8_t *)(self + off), r, base);
        injected++;
    }
    if (cnt < 4) {
        cnt++;
        mfLog(@"[stobs] ✍️ 配方 '%s' 注入 %d/%d ivar (off0=0x%llx off1=0x%llx size=%u)",
              r->name, injected, ntarget, offs[0], offs[1], r->struct_size);
    }
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

// 安装: 开关开时, 按活动配方 hook 其选择器(序言字节匹配才装, 双门控, 无 bundleID 明文)
void mfProbeInstall(void) {
    static BOOL done = NO;
    if (done) return;
    if (!mfStateObsIsOn()) return;                 // 开关门控(默认关): 静默跳过
    const MFInjectRecipe *r = g_mfRecipe;
    if (!r || !r->sel_off) return;
    uintptr_t base = mfProbeMainBase();
    if (!base) return;
    uintptr_t target = base + r->sel_off;

    // 序言字节校验(配方提供): 不匹配 = 非目标进程/地址漂移 → 拒绝 hook
    if (r->prologue && memcmp((void *)target, r->prologue, 16) != 0) return;  // 静默跳过

    g_mfStObsCont = (void *)(target + 0x10);

    uint8_t stub[16];
    uint32_t ldr = 0x58000050, br = 0xd61f0200;
    uint64_t tramp = (uint64_t)(uintptr_t)mf_stObsTramp;
    memcpy(stub, &ldr, 4); memcpy(stub + 4, &br, 4); memcpy(stub + 8, &tramp, 8);

    NSString *err = nil;
    if (mfProbePatch16(target, stub, &err)) {
        done = YES;
        mfLog(@"[stobs] ✅ hook_inject 配方 '%s' 装载 @ %p → tramp %p", r->name, (void *)target, (void *)tramp);
    } else {
        mfLog(@"[stobs] ⛔ hook 失败: %@", err);
    }
}
