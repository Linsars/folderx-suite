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
#import <stdlib.h>
#import <stdio.h>
#import <dlfcn.h>

extern void mfLog(NSString *fmt, ...);

// v2.58.157: 「运行时状态观测」独立开关已废除 —— 状态注入并入 patch 引擎判定点体系。
//   侦查(sk2recipe)扫出配方 → 注册为 hookinj@ 判定点(默认 off) → 用户在判定点列表 ⚡ 执行
//   → apEntDumpsApply/mfAPEntPatchNow 调 mfProbeInstallRecipe 装 hook。与其他判定点同一交互。
//   一次性清理 155 遗留的 mfInjectRecipes prefs 存储(旧独立存储已废)。
static void mfProbePurgeLegacyStore(void) {
    static BOOL done = NO; if (done) return; done = YES;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    if ([ud objectForKey:@"mfInjectRecipes"]) {
        [ud removeObjectForKey:@"mfInjectRecipes"];
        [ud removeObjectForKey:@"mfInjectRecipesSV"];
        [ud removeObjectForKey:@"mfStateObsEnabled"];
        [ud synchronize];
        mfLog(@"[stobs] 清理旧独立存储 mfInjectRecipes(状态注入已并入判定点引擎)");
    }
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
    MF_FLD_F64,        // double(固定值)
    MF_FLD_IMMSTR,     // immortal String storage 指针 = (base + arg) | 0x8000000000000000
    MF_FLD_NOWPLUS,    // double 有效期 = (当前时间 + arg 年) 毫秒 since 1970(运行时算, 不写死魔数)
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
            case MF_FLD_NOWPLUS: {
                // 运行时: 当前时间 + arg 年, 毫秒 since 1970(不依赖魔数, 避开签发时间区间校验穿帮)
                double ms = ([[NSDate date] timeIntervalSince1970] + (double)f->arg * 365.25 * 86400.0) * 1000.0;
                memcpy(p + f->off, &ms, 8);
                break;
            }
        }
    }
}

// ===================== 配方持久层(数据注册, 对齐 manual 录入范式) =====================
//   prefs 键 mfInjectRecipes = 配方 JSON 数组。运行时 install 时解析首个启用配方为 C 结构缓存,
//   热路径注入用缓存的 C 结构(不在每次选择器调用里做字典解析)。
//   配方来源: ① 内置种子(首次运行写入 prefs, 之后即数据可改/可删)
//             ② 侦查引擎产出(下一步) ③ 人工录入(mfInjectRecipeManualAdd)。
// 内置种子/独立存储已废除(v2.58.157): 配方改由侦查 sk2recipe 注册为 hookinj@ 判定点,
//   内嵌在 mfEntDumps 点位里, 用户 ⚡ 执行。此处只保留 dict→C 结构解析器。

static uint64_t mfParseU64(id v) {
    if ([v isKindOfClass:[NSNumber class]]) return [v unsignedLongLongValue];
    if ([v isKindOfClass:[NSString class]]) return strtoull([v UTF8String], NULL, 0);
    return 0;
}

// 解析配方字典 → malloc 的 C 结构(进程生命期常驻, 不释放)。失败返 NULL。
static const MFInjectRecipe *mfParseRecipe(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NULL;
    NSArray *fields = d[@"fields"];
    if (![fields isKindOfClass:[NSArray class]] || fields.count == 0) return NULL;

    MFInjectRecipe *r = calloc(1, sizeof(MFInjectRecipe));
    MFField *fs = calloc(fields.count, sizeof(MFField));
    r->fields = fs; r->n_fields = (int)fields.count;
    r->name = strdup([(d[@"name"] ?: @"?") UTF8String]);
    r->sel_off = mfParseU64(d[@"selOff"]);
    r->struct_size = (uint32_t)mfParseU64(d[@"structSize"]);
    // prologue hex → 16 字节
    NSString *ph = d[@"prologue"];
    if ([ph isKindOfClass:[NSString class]] && ph.length >= 32) {
        uint8_t *pb = calloc(1, 16);
        for (int i = 0; i < 16; i++) {
            char hx[3] = { [ph characterAtIndex:i*2], [ph characterAtIndex:i*2+1], 0 };
            pb[i] = (uint8_t)strtoul(hx, NULL, 16);
        }
        r->prologue = pb;
    }
    // ivarGlobals
    NSArray *igs = d[@"ivarGlobals"];
    for (int i = 0; i < 4 && [igs isKindOfClass:[NSArray class]] && i < (int)igs.count; i++)
        r->ivar_globals[i] = mfParseU64(igs[i]);
    // fields
    for (int i = 0; i < r->n_fields; i++) {
        NSDictionary *f = fields[i];
        fs[i].off = (uint32_t)mfParseU64(f[@"off"]);
        NSString *ty = f[@"type"];
        if ([ty isEqualToString:@"u8"])      { fs[i].type = MF_FLD_U8;     fs[i].arg = mfParseU64(f[@"v"]); }
        else if ([ty isEqualToString:@"u64"]){ fs[i].type = MF_FLD_U64;    fs[i].arg = mfParseU64(f[@"v"]); }
        else if ([ty isEqualToString:@"immstr"]){ fs[i].type = MF_FLD_IMMSTR; fs[i].arg = mfParseU64(f[@"v"]); }
        else if ([ty isEqualToString:@"now_plus"]){ fs[i].type = MF_FLD_NOWPLUS; fs[i].arg = mfParseU64(f[@"years"] ?: @(100)); }
        else if ([ty isEqualToString:@"f64"]){ fs[i].type = MF_FLD_F64;    fs[i].f64 = [f[@"f"] doubleValue]; }
        else if ([ty isEqualToString:@"bytes"]) {
            fs[i].type = MF_FLD_BYTES;
            const char *s = [(f[@"s"] ?: @"") UTF8String];
            uint32_t bl = (uint32_t)strlen(s);
            char *cp = malloc(bl + 1); memcpy(cp, s, bl + 1);
            fs[i].bytes = cp; fs[i].blen = bl;
        } else { free(fs); free(r); return NULL; }   // 未知类型 → 拒绝(防注入垃圾)
    }
    return r;
}

// —— 活动配方: 由 patch 引擎在执行 hookinj@ 判定点时注入(不再从独立 prefs 读) ——
static const MFInjectRecipe *g_mfActiveRecipe = NULL;
static BOOL mfProbePatch16(uintptr_t target, const uint8_t *newBytes, NSString **err);  // fwd
extern void mf_stObsTramp(void);       // asm trampoline(定义在下方)
extern void *g_mfStObsCont;            // = target+0x10(定义在下方)

// patch 引擎回调: 传入 hookinj 配方字典 → 解析并装 inline hook(判定点 ⚡ 执行路径调用)。
//   返回 YES=hook 装上。序言字节校验防漂移/误注入。与其他判定点 patch 同一交互层。
BOOL mfProbeInstallRecipe(NSDictionary *recipeDict) {
    mfProbePurgeLegacyStore();
    const MFInjectRecipe *r = mfParseRecipe(recipeDict);
    if (!r || !r->sel_off) { mfLog(@"[stobs] ⛔ 配方解析失败或缺 selOff"); return NO; }
    uintptr_t base = mfProbeMainBase();
    if (!base) return NO;
    uintptr_t target = base + r->sel_off;
    if (r->prologue && memcmp((void *)target, r->prologue, 16) != 0) {
        mfLog(@"[stobs] ⛔ 序言不匹配(地址漂移/非目标), 拒绝 hook @ %#llx", (unsigned long long)r->sel_off);
        return NO;
    }
    static BOOL hooked = NO;
    g_mfActiveRecipe = r;                       // 先设活动配方(logger 用)
    if (hooked) { mfLog(@"[stobs] 配方已切换为 '%s'(hook 已在, 复用)", r->name); return YES; }
    g_mfStObsCont = (void *)(target + 0x10);
    uint8_t stub[16];
    uint32_t ldr = 0x58000050, br = 0xd61f0200;
    uint64_t tramp = (uint64_t)(uintptr_t)mf_stObsTramp;
    memcpy(stub, &ldr, 4); memcpy(stub + 4, &br, 4); memcpy(stub + 8, &tramp, 8);
    NSString *err = nil;
    if (mfProbePatch16(target, stub, &err)) {
        hooked = YES;
        mfLog(@"[stobs] ✅ hookinj 判定点装载 '%s' @ %p → tramp %p", r->name, (void *)target, (void *)tramp);
        return YES;
    }
    mfLog(@"[stobs] ⛔ hook 失败: %@", err);
    return NO;
}

// self = x20(状态管理实例) → 入口按活动配方注入(注入不限次, 覆盖 app sync 回写)
void mf_stObsLog(void *selfPtr) {
    static uint32_t cnt = 0;
    uintptr_t self = (uintptr_t)selfPtr;
    uintptr_t base = mfProbeMainBase();
    if (!self || !base) return;
    const MFInjectRecipe *r = g_mfActiveRecipe;
    if (!r) return;

    size_t isz = malloc_size((void *)self);
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

// 安装入口(v2.58.157): 状态注入已并入 patch 引擎, 由 mfProbeInstallRecipe(判定点 ⚡)驱动。
//   保留空 mfProbeInstall 供 ctor 旧调用点安全空转 + 清理旧独立存储。
void mfProbeInstall(void) {
    mfProbePurgeLegacyStore();   // 清 155 遗留的 mfInjectRecipes/mfStateObsEnabled
}
