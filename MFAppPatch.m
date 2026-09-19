// MFAppPatch.m — 进程层 patch 引擎 (v2.21.0, 2026-09-04)
// 灵感来源: 第三方补丁工具的逆向观察 (vm_protect 写 __text 模式) — 详见本地 recon 报告
// 【归属】IAPtools.dylib (IAP 域); 实验模拟页入口; 不碰系统进程
// 【铁律】ctor 有系统进程守卫(IAPtools 既有); 本文件不新增 ctor, 由 MFPanel ctor 按开关拉起
//
// 三层能力:
//   1. 规则引擎: prefs 读 JSON 规则表, bundleID+version 匹配当前进程
//   2. 执行器:   kind=method → objc swizzle;  kind=text → vm_protect(RW)+写字节+icache+恢复RX
//   3. 采集器:   纯被动周期快照 diff (v2.21: 不 hook vm_protect — fishhook 会污染
//                该工具的 backtrace 反 hook 检测会导致其 abort (实测)
//
// 规则表格式 (prefs key = mfAppPatchRules, 值 = JSON 字符串):
// [{
//   "bid": "<目标 bundle id>", "ver": "<版本>", "note": "<说明>",
//   "patches": [
//     {"kind":"method","cls":"ProGateChecker","sel":"isPro","ret":true},
//     {"kind":"text","off":"0x12345678","old":"1f2003d5","new":"20008052c0035fd6"}
//   ]
// }]

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>   // v2.57: nlist_64/N_SECT(swifttext 符号解析) — 必须在 dyld.h 后
#import <objc/runtime.h>
#import <libkern/OSCacheControl.h>
#import <Security/Security.h>   // v2.56: SecItemCopyMatching hook(样本授权判定数据源)
#import "fishhook.h"            // v2.56: fishhook rebind(样本判定链解锁)
#import <objc/message.h>        // v2.56.3: objc_msgSend(CloudKit hook 运行时构造 CKRecordID)
#include <sys/sysctl.h>
#include <dlfcn.h>              // v2.57: dlfcn 补回(上一步 edit 误删)

#import "MFPanel.h"

// v2.56.3: per-app 开关化 —— patch 引擎/采集器开关从全局键改为 per-app 键
//   (<base>_<bid>, 如 mfAppPatchEnabled_com.scripting.ios)。用户反馈: 全局键导致
//   A app 打开, B app 呼出面板还是开的。无全局 fallback —— 每个 app 独立。
static NSString *apCurBundleID(void); // fwd (定义于下方)
static NSString *apPrefKey(NSString *base) {
    NSString *bid = apCurBundleID();
    return [NSString stringWithFormat:@"%@_%@", base, bid];
}
BOOL mfAppPatchIsOn(void) {
    return mfPrefBool(apPrefKey(@"mfAppPatchEnabled"), NO);
}
long mfAppPatchHits(void); // fwd
void apInstallCollectors(void); // fwd
void mfAppPatchSectionInLabPage(UIView *page, CGFloat *yio); // fwd
NSString *mfAppPatchRulesJSON(void);
void mfAppPatchSetRulesJSON(NSString *json);

// ====== 偏好 ======
static NSString *MFPrefsPath(void) {
    // ★v2.56.2 修复: 曾写成 /var/mobile/...(无 /var/jb)导致规则读写落在错误文件,
    //   mfAppPatchRules 永远保存不进去(开关 Enabled 在 /var/jb 文件, 规则却读 /var/mobile)。
    //   与 mfPrefsDict/mfSetPrefs(MFPanel.m)统一为 /var/jb/var/mobile/...
    return @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist";
}
static id mfReadPrefObj(NSString *key) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:MFPrefsPath()];
    return d[key];
}
static void mfWritePrefObj(NSString *key, id val) {
    NSMutableDictionary *d = [[NSDictionary dictionaryWithContentsOfFile:MFPrefsPath()] mutableCopy] ?: [NSMutableDictionary dictionary];
    if (val) d[key] = val; else [d removeObjectForKey:key];
    [d writeToFile:MFPrefsPath() atomically:YES];
}
// v2.58.70: 墓碑(fwd) — 定义在下方, apEntDumpsLoad/Merge 先用
static NSString *apCurBundleID(void);
static NSArray *apTombstones(void);
static void apTombstoneAdd(NSString *sym);
// v2.58.77: 墓碑可恢复(单向门是缺陷) — 定义在下方, 卡片/恢复入口先用
NSUInteger mfAppPatchTombstoneCount(void);
void mfAppPatchTombstonesClear(void);
void mfAppPatchTombstoneRemove(NSString *sym);

// ====== 状态 ======
static long g_apHits = 0;          // 成功 patch 数
static long g_apProPhit = 0;       // v2.58.84: 序言形态拒绝计数(诊断用)
static long g_apCollHits = 0;      // 采集到的外部 patch 数
static BOOL g_apCollInstalled = NO;
static NSMutableArray *g_apLog = nil;   // 最近 50 条日志
static NSObject *g_apLock = nil;

static void apLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void apLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!g_apLock) g_apLock = [NSObject new];
    @synchronized (g_apLog) {
        if (!g_apLog) g_apLog = [NSMutableArray new];
        [g_apLog insertObject:[NSString stringWithFormat:@"%@ %@", [NSDate date], s] atIndex:0];
        if (g_apLog.count > 50) [g_apLog removeLastObject];
    }
    mfLog(@"[AppPatch] %@", s);
}
long mfAppPatchHits(void) { return g_apHits; }

// ====== 工具: hex string <-> bytes (纯 C 解析, 避开 SDK selector 可见性怪问题) ======
// v2.58.71: mfLeHex(内存序 hex) — MFRecon.m 同名 static 的本文件副本(跨文件 static 不可见)
static NSString *mfLeHex(uint32_t w) {
    return [NSString stringWithFormat:@"%02x%02x%02x%02x",
            w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, (w >> 24) & 0xFF];
}
static NSMutableData *apHexToBytes(NSString *hex) {
    NSMutableData *d = [NSMutableData data];
    if (![hex isKindOfClass:[NSString class]]) return d;
    const unsigned char *s = (const unsigned char*)hex.UTF8String;
    if (!s) return d;
    int hi = -1; // -1 = 待高半字节
    for (const unsigned char *p = s; *p; p++) {
        unsigned char c = *p; int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else if (c == ' ' || c == '\t' || c == '\n') continue;
        else return [NSMutableData data]; // 非法字符
        if (hi < 0) { hi = v; }
        else { unsigned char b = (unsigned char)((hi << 4) | v); [d appendBytes:&b length:1]; hi = -1; }
    }
    if (hi >= 0) return [NSMutableData data]; // 奇数长度
    return d;
}
static NSString *apBytesToHex(const void *bytes, NSUInteger len) {
    if (!bytes || !len) return @"";
    NSMutableString *s = [NSMutableString stringWithCapacity:len * 3];
    const unsigned char *b = bytes;
    for (NSUInteger i = 0; i < len; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

// ====== 当前 app 信息 ======
static NSString *apCurBundleID(void) {
    return [[NSBundle mainBundle] bundleIdentifier] ?: @"";
}
static NSString *apCurVersion(void) {
    return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
}

// ====== Mach-O 主程序定位 (MH_EXECUTE, 同款思路) ======
static uintptr_t apMainImageBase(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE) return (uintptr_t)h;
    }
    return _dyld_image_count() ? (uintptr_t)_dyld_get_image_header(0) : 0;
}

// ====== text patch: vm_protect 三步 ======
// v2.57: 抽出 apTextPatchAt(绝对地址) — 主程序(text 规则)与框架(swifttext 规则)共用执行核
static BOOL apTextPatchAt(uintptr_t target, NSData *expectOld, NSData *newBytes, NSString **err) {
    if (expectOld.length) {
        NSData *cur = [NSData dataWithBytes:(void*)target length:expectOld.length];
        if (![cur isEqualToData:expectOld]) {
            *err = [NSString stringWithFormat:@"old mismatch @%p: cur=%@ want=%@", (void*)target, apBytesToHex(cur.bytes, cur.length), apBytesToHex(expectOld.bytes, expectOld.length)];
            return NO;
        }
    }
    uint32_t pre = 0; BOOL hadPre = NO;
    if (newBytes.length >= 4) { pre = *(const uint32_t *)target; hadPre = YES; }   // v2.58.82: 改前值
    // v2.58.82: 跨页保护 — 4 字节 patch 落在页尾 1~3 字节时需要保护两页
    uintptr_t pgA = target & ~0xFFFUL;
    uintptr_t pgB = (target + newBytes.length - 1) & ~0xFFFUL;
    vm_size_t span = (vm_size_t)(pgB - pgA) + 0x1000;
    kern_return_t kr = vm_protect(mach_task_self(), pgA, span, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        *err = [NSString stringWithFormat:@"vm_protect RW failed kr=%d", kr];
        return NO;
    }
    memcpy((void*)target, newBytes.bytes, newBytes.length);
    sys_icache_invalidate((void*)target, newBytes.length);
    // ★回读校验 — 三轮"patch OK 却不亮"的核心疑点: 所有成功都是自报, 从未独立回读内存。
    //   注意: 先恢复 RX 再判返回值 — 否则失败路径会把该页留在"可写不可执行"状态,
    //   该页代码一执行就崩(v2.58.82 自查修正: 初版在恢复前 return NO, 会毁掉其它点)。
    BOOL land = YES; uint32_t want = 0, post = 0;
    if (hadPre) {
        memcpy(&want, newBytes.bytes, 4);
        post = *(const uint32_t *)target;   // 真·内存回读
        land = (post == want);
    }
    apLog(@"[verify] %p pre=%08x want=%08x post=%08x %@",
          (void*)target, pre, want, post, land ? @"✓字节已落地" : @"✗未落地(写失败)");
    kr = vm_protect(mach_task_self(), pgA, span, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        *err = [NSString stringWithFormat:@"vm_protect RX restore failed kr=%d", kr];
        return NO; // 字节已写, 权限没恢复 — 仍算半成功
    }
    if (!land) {
        *err = [NSString stringWithFormat:@"readback mismatch @%p: post=%08x want=%08x", (void*)target, post, want];
        return NO;
    }
    return YES;
}
static BOOL apTextPatch(uintptr_t fileOffAddr, NSData *expectOld, NSData *newBytes, NSString **err) {
    // off 是相对主程序加载基址的 vm offset
    uintptr_t base = apMainImageBase();
    if (!base) { *err = @"no main image"; return NO; }
    return apTextPatchAt(base + fileOffAddr, expectOld, newBytes, err);
}

// ====== v2.57: 框架符号解析 + swifttext patch (链B交卷能力) ======
// 镜像内符号表解析: LC_SYMTAB + __LINKEDIT slide 换算, 返回符号 vmaddr(镜像偏移)。
// 侦查卡(F8)与 swifttext 执行器共用 — 定位能力单一实现。
uintptr_t mfApSymVMAddr(const void *mh, const char *symName) {
    if (!mh || !symName) return 0;
    const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
    if (h->magic != MH_MAGIC_64) return 0;
    const struct load_command *lc = (const struct load_command *)((const uint8_t *)h + sizeof(struct mach_header_64));
    uint32_t symoff = 0, nsyms = 0, stroff = 0;
    int64_t linkeditDelta = 0;   // vmaddr - fileoff: 文件偏移 → vmaddr 的换算常数
    for (uint32_t c = 0; c < h->ncmds; c++, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
        if (lc->cmd == LC_SYMTAB) {
            const struct symtab_command *st = (const struct symtab_command *)lc;
            symoff = st->symoff; nsyms = st->nsyms; stroff = st->stroff;
        } else if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (!strcmp(sg->segname, "__LINKEDIT"))
                linkeditDelta = (int64_t)sg->vmaddr - (int64_t)sg->fileoff;
        }
    }
    if (!nsyms || !symoff) return 0;
    // 符号表在内存 = _dyld 已把整个 LINKEDIT 按文件布局映射: fileoff X 处的字节
    // 落在 vmaddr = X + linkeditDelta, 再加 slide。这里返回 vmaddr(不含 slide)由调用方组合。
    const struct nlist_64 *syms = (const struct nlist_64 *)((const uint8_t *)h + symoff + linkeditDelta);
    const char *strtab = (const char *)((const uint8_t *)h + stroff + linkeditDelta);
    // n_value 是镜像内 vmaddr — 对 __TEXT vmaddr=0 的标准 dylib 直接可用
    for (uint32_t i = 0; i < nsyms; i++) {
        if (!(syms[i].n_type & N_SECT) || !syms[i].n_value) continue;
        const char *nm = strtab + syms[i].n_un.n_strx;
        if (nm && !strcmp(nm, symName)) return (uintptr_t)syms[i].n_value;
    }
    return 0;
}

// swifttext 执行器: 按镜像名+符号名定位函数 → vm_protect 三步 patch 函数头
// 规则: {"kind":"swifttext","img":"ScriptingKit","sym":"_$s12...hasValidD5Token...","new":"20008052c0035fd6"}
//   old 可选(带 = 字节验证双保险; 不带 = 符号定位唯一保险)
// patch 目标必须是 Swift 直呼函数(class method 非动态派发, bl 直达函数地址 —
// hasValidToken/hasPro 均为此类, PurchaseManager.isProEnabled 直接 bl 汇聚点已实锤)
// v2.58.9 F8v2: sym 以 "@0x" 开头 = strip 二进制合成名 — 无符号表可查, 直接用
// dump 内 vmaddr(镜像内偏移)+slide 定位, 与 F8v2 扫描器(链B引擎直打分支)配套
// v2.58.30: apSwiftTextPatch 加 dump 直打分支 — 合成 sym(ivarRead@/ivarGetter@)
// 无符号表可查, strip 主二进制 mfApSymVMAddr 必 miss("symbol not in XXX" 空转
// 2.58.27/28 两轮实锤)。zap/Boot 两路都从 entDumps 拿 dump 字典, vmaddr+slide
// 直打 — 与 @0x 前缀同一地址口径(镜像内偏移+slide)。
static BOOL apSwiftTextPatchDump(NSDictionary *d, NSData *oldBytes, NSData *newBytes, NSString **err) {
    if (!d[@"vmaddr"]) { *err = @"dump 缺 vmaddr"; return NO; }
    NSString *imgName = d[@"img"] ?: @"";
    // 1. 找镜像(与 apSwiftTextPatch 同口径)
    const struct mach_header *mh = NULL; intptr_t slide = 0;
    const char *want = imgName.UTF8String;
    uint32_t ic = _dyld_image_count();
    for (uint32_t i = 0; i < ic; i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, want)) { mh = _dyld_get_image_header(i); slide = _dyld_get_image_vmaddr_slide(i); break; }
    }
    if (!mh) { *err = [NSString stringWithFormat:@"image %@ not loaded", imgName]; return NO; }
    // 2. 直打: vmaddr(镜像内偏移, 静态) + 当前镜像 slide — ASLR 每次启动不同,
    //    存的 slide 快照只在当次会话有效, 冷启动必过期(mf_debug_31 实锤:
    //    Boot 重打用旧 slide → abs 错 → vm_protect RW failed kr=1)
    uintptr_t vmAddr = (uintptr_t)[d[@"vmaddr"] unsignedLongLongValue];
    uintptr_t abs = vmAddr + (uintptr_t)slide;
    BOOL ok = apTextPatchAt(abs, oldBytes, newBytes, err);
    if (ok) apLog(@"[swifttext] %@ %@ vmaddr=%#lx abs=%#lx → patch OK", imgName, [d[@"sym"] lastPathComponent], (unsigned long)vmAddr, (unsigned long)abs);
    return ok;
}
static BOOL apSwiftTextPatch(NSString *imgName, NSString *symName, NSData *oldBytes, NSData *newBytes, NSString **err) {
    if (imgName.length < 3 || symName.length < 4 || newBytes.length < 4) { *err = @"bad swifttext args"; return NO; }
    // 1. 找镜像(名字 contains — ScriptingKit 匹配 "…/Scripting.app/Frameworks/ScriptingKit.framework/ScriptingKit")
    const struct mach_header *mh = NULL;
    intptr_t slide = 0;
    const char *want = imgName.UTF8String;
    uint32_t ic = _dyld_image_count();
    for (uint32_t i = 0; i < ic; i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, want)) {
            mh = _dyld_get_image_header(i);
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!mh) { *err = [NSString stringWithFormat:@"image %@ not loaded", imgName]; return NO; }
    // 2. 符号解析 → 绝对地址
    uintptr_t vmAddr = 0;
    if ([symName hasPrefix:@"@0x"] || [symName hasPrefix:@"@0X"]) {
        // F8v2 直打: sym 本身就是 vmaddr(镜像内偏移, 侦查时带 slide 存库)
        vmAddr = (uintptr_t)strtoull(symName.UTF8String + 1, NULL, 16);
    } else {
        vmAddr = mfApSymVMAddr(mh, symName.UTF8String);
    }
    if (!vmAddr) { *err = [NSString stringWithFormat:@"symbol not in %@", imgName]; return NO; }
    uintptr_t abs = vmAddr + (uintptr_t)slide;
    // 3. 执行 patch
    BOOL ok = apTextPatchAt(abs, oldBytes, newBytes, err);
    if (ok) apLog(@"[swifttext] %@ %@ vmaddr=%#lx abs=%#lx → patch OK", imgName, symName.lastPathComponent, (unsigned long)vmAddr, (unsigned long)abs);
    return ok;
}

// ====== objc hook: 把方法 IMP 换成常量返回 ======
static long g_apStubTrue = 0, g_apStubFalse = 0;
static void apStubTrue(id self, SEL _cmd) { g_apStubTrue++; }
static BOOL apStubTrueB(id self, SEL _cmd) { g_apStubTrue++; return YES; }
static void apStubFalse(id self, SEL _cmd) { g_apStubFalse++; }
static BOOL apStubFalseB(id self, SEL _cmd) { g_apStubFalse++; return NO; }

static BOOL apMethodPatch(NSString *clsName, NSString *selName, BOOL ret, NSString **err) {
    Class cls = NSClassFromString(clsName);
    if (!cls) { *err = [NSString stringWithFormat:@"class %@ not found", clsName]; return NO; }
    SEL sel = NSSelectorFromString(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) m = class_getClassMethod(cls, sel);
    if (!m) { *err = [NSString stringWithFormat:@"method %@/%@ not found", clsName, selName]; return NO; }
    char retType = method_copyReturnType(m)[0];
    IMP newImp;
    if (retType == 'B' || retType == 'c') newImp = ret ? (IMP)apStubTrueB : (IMP)apStubFalseB;
    else newImp = ret ? (IMP)apStubTrue : (IMP)apStubFalse;
    method_setImplementation(m, newImp);
    return YES;
}

// ====== v2.56: Keychain 授权豁免(学习自样本判定链数据源) ======
// 样本授权判定: fetchUserRecordID(CloudKit 身份) + SecItemCopyMatching(Keychain 缓存)
// hook SecItemCopyMatching → 恒"找到授权项"(errSecSuccess + 伪 data) → 样本/主进程判定"已授权"
static OSStatus (*g_origSecCopyMatching)(CFDictionaryRef, CFTypeRef *) = NULL;
// v2.56.7: dlsym hook 前向声明(kc Install 先于定义使用)
static void *(*g_origDlsym)(void *, const char *) = NULL;
static void *apDlsymHook(void *handle, const char *name);
static OSStatus apSecCopyMatchingHook(CFDictionaryRef query, CFTypeRef *result) {
    // v2.56.5: 记录 query 关键字段——判定链样本装载后, 看它到底查什么(service/account/返回类型),
    //   才知道该怎么伪造正确格式的数据("OK" 2 字节可能不是样本期望的结构)。
    if (g_apHits < 64) {
        NSString *svc = @"?";
        NSString *acct = @"?";
        NSString *cls = @"?";
        NSString *retData = @"?";
        if (query) {
            CFTypeRef v;
            if ((v = CFDictionaryGetValue(query, kSecAttrService))) svc = (__bridge NSString *)v;
            if ((v = CFDictionaryGetValue(query, kSecAttrAccount))) acct = (__bridge NSString *)v;
            if ((v = CFDictionaryGetValue(query, kSecClass))) cls = (__bridge NSString *)v;
            if (CFDictionaryContainsKey(query, kSecReturnData)) retData = @"RETURN_DATA";
            if (CFDictionaryContainsKey(query, kSecReturnRef)) retData = @"RETURN_REF";
        }
        apLog(@"[keychain] consult q: cls=%@ svc=%@ acct=%@ %@", cls, svc, acct, retData);
    }
    g_apHits++;
    // 恒授权: 返回"找到"+伪造数据(空 data 通常代表"已存授权")
    if (result) {
        CFDataRef fake = CFDataCreate(NULL, (const uint8_t *)"OK", 2);
        *result = fake;
    }
    return errSecSuccess;
}
static void apKeychainInstall(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        struct rebinding rb = {"SecItemCopyMatching", (void *)apSecCopyMatchingHook, (void **)&g_origSecCopyMatching};
        int r = rebind_symbols(&rb, 1);
        apLog(@"[keychain] SecItemCopyMatching rebind: %d (orig=%p)", r, g_origSecCopyMatching);
        // v2.56.7: 样本用 dlsym 动态解析 SecItemCopyMatching(fishhook 只改 GOT, 拦不到
        //   dlsym 拿到的真函数指针 → consult 0 命中的根因)。补 hook dlsym 本身:
        //   样本 dlsym("SecItemCopyMatching") 时直接返回我们的 hook(记录 query+恒授权)。
        struct rebinding rb2 = {"dlsym", (void *)apDlsymHook, (void **)&g_origDlsym};
        int r2 = rebind_symbols(&rb2, 1);
        apLog(@"[keychain] dlsym rebind: %d (orig=%p)", r2, g_origDlsym);
    });
}

// v2.56.7: dlsym hook——样本动态解析授权函数时返我们的实现(绕不过去)
static int g_apDlsymN = 0;
static void *apDlsymHook(void *handle, const char *name) {
    if (name) {
        if (!strcmp(name, "SecItemCopyMatching") || !strcmp(name, "SecItemCopyMatchingWithAttributes")) {
            if (g_apDlsymN++ < 16)
                apLog(@"[dlsym] %s -> KEYCHAIN HOOK (样本要授权函数, 直接给 hook)", name);
            return (void *)apSecCopyMatchingHook;
        }
        if (!strcmp(name, "mach_msg_server")) {
            if (g_apDlsymN++ < 16)
                apLog(@"[dlsym] mach_msg_server -> passthrough (记录用)");
            return g_origDlsym ? g_origDlsym(handle, name) : NULL;
        }
        if (g_apDlsymN < 32)
            apLog(@"[dlsym] %s handle=%p", name, handle);
    }
    return g_origDlsym ? g_origDlsym(handle, name) : NULL;
}

// v2.56.3: CloudKit 授权豁免 —— hook CKContainer fetchUserRecordIDWithCompletionHandler:
//   恒回调"本机已授权 cloudid"(样本判定链另一腿: CloudKit 身份 + Keychain 缓存)。
//   Keychain(v2.56.0)已 hook, 此补 CloudKit: 返回真实本机 recordID(名单内 → 判定授权)。
//   纯运行时(NSClassFromString + method_setImplementation), 不引入编译依赖。
static void (*g_origKitFetch)(id, SEL, id) = NULL;
static NSString *apCloudKitFakeID(void) {
    // 可配置: prefs mfCloudKitFakeID; 默认用户提供的本机 Scripting cloudid
    id v = mfReadPrefObj(@"mfCloudKitFakeID");
    if ([v isKindOfClass:[NSString class]] && [(NSString *)v length]) return v;
    return @"cloudid_6fa82d041cdb54b2f3e558828754bf08";
}
static void apCloudKitFetchHook(id self, SEL _cmd, id completion) {
    apLog(@"[cloudkit] fetchUserRecordID consult (authorize->yes, fake=%@)", apCloudKitFakeID());
    g_apHits++;
    if (!completion) return;
    @try {
        Class rCls = NSClassFromString(@"CKRecordID");
        id rec = nil;
        if (rCls) {
            SEL initSel = NSSelectorFromString(@"initWithRecordName:");
            rec = ((id (*)(id, SEL, id))objc_msgSend)([rCls alloc], initSel, apCloudKitFakeID());
        } else {
            apLog(@"[cloudkit] CKRecordID class not found");
        }
        void (^blk)(id, id) = (void (^)(id, id))completion;
        blk(rec, nil);
    } @catch (NSException *e) {
        apLog(@"[cloudkit] hook cb exc: %@", e.reason);
    }
}
static void apCloudKitInstall(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // rootless: /var/jb/System 优先, 兜底 /System (动态加载器有路径解析)
        dlopen("/var/jb/System/Library/Frameworks/CloudKit.framework/CloudKit", RTLD_NOW);
        dlopen("/System/Library/Frameworks/CloudKit.framework/CloudKit", RTLD_NOW);
        Class cls = NSClassFromString(@"CKContainer");
        if (!cls) { apLog(@"[cloudkit] CKContainer class not found"); return; }
        SEL sel = NSSelectorFromString(@"fetchUserRecordIDWithCompletionHandler:");
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) { apLog(@"[cloudkit] fetchUserRecordID method not found"); return; }
        g_origKitFetch = (void (*)(id, SEL, id))method_getImplementation(m);
        method_setImplementation(m, (IMP)apCloudKitFetchHook);
        apLog(@"[cloudkit] fetchUserRecordID hooked (orig=%p)", g_origKitFetch);
    });
}

// ====== 规则执行 ======
static void apApplyRules(void) {
    @try {
        NSString *rulesJSON = mfReadPrefObj(@"mfAppPatchRules");
        if (![rulesJSON isKindOfClass:[NSString class]] || rulesJSON.length < 5) return;
        NSData *rd = [rulesJSON dataUsingEncoding:NSUTF8StringEncoding];
        NSArray *rules = [NSJSONSerialization JSONObjectWithData:rd options:0 error:nil];
        if (![rules isKindOfClass:[NSArray class]]) return;
        NSString *curBid = apCurBundleID();
        NSString *curVer = apCurVersion();
        for (NSDictionary *rule in rules) {
            if (![rule isKindOfClass:[NSDictionary class]]) continue;
            NSString *bid = rule[@"bid"];
            if (![bid isEqualToString:curBid]) continue;
            NSString *rv = rule[@"ver"];
            if (rv.length && ![rv isEqualToString:curVer]) {
                apLog(@"ver gate: rule=%@ cur=%@ skip", rv, curVer);
                continue;
            }
            BOOL ruleOn = mfPrefBool([NSString stringWithFormat:@"mfAppPatch_%@", bid], YES);
            if (!ruleOn) { apLog(@"rule disabled: %@", bid); continue; }
            NSArray *patches = rule[@"patches"];
            for (NSDictionary *p in patches) {
                if (![p isKindOfClass:[NSDictionary class]]) continue;
                NSString *kind = p[@"kind"] ?: @"";
                NSString *err = nil;
                BOOL ok = NO;
                if ([kind isEqualToString:@"method"]) {
                    ok = apMethodPatch(p[@"cls"] ?: @"", p[@"sel"] ?: @"", [p[@"ret"] boolValue], &err);
                } else if ([kind isEqualToString:@"text"]) {
                    NSString *offS = p[@"off"] ?: @"";
                    unsigned long long off = strtoull(offS.UTF8String, NULL, 16);
                    NSData *old = apHexToBytes(p[@"old"] ?: @"");
                    NSData *new = apHexToBytes(p[@"new"] ?: @"");
                    if (!new.length) err = @"empty new bytes";
                    else ok = apTextPatch((uintptr_t)off, old, new, &err);
                } else if ([kind isEqualToString:@"swifttext"]) {
                    // v2.57: 框架内 Swift 符号定位 patch(链B能力: 扫描→定位→patch→持久化)
                    NSData *old = apHexToBytes(p[@"old"] ?: @"");
                    NSData *new = apHexToBytes(p[@"new"] ?: @"");
                    if (!new.length) err = @"empty new bytes";
                    else ok = apSwiftTextPatch(p[@"img"] ?: @"", p[@"sym"] ?: @"", old, new, &err);
                } else if ([kind isEqualToString:@"keychain"]) {
                    // v2.56: Keychain 授权豁免(样本判定链数据源)
                    apKeychainInstall();
                    ok = YES;   // 全局生效(进程内)
                } else if ([kind isEqualToString:@"cloudkit"]) {
                    // v2.56.3: CloudKit 授权豁免(样本判定链另一腿: 云端身份)
                    apCloudKitInstall();
                    ok = YES;   // 全局生效(进程内)
                }
                if (ok) { g_apHits++; apLog(@"✓ %@ patch applied", kind); }
                else apLog(@"✗ %@ failed: %@", kind, err);
            }
        }
    } @catch (NSException *e) {
        apLog(@"apply exc: %@", e.reason);
    }
}

// 引擎拉起: v2.58 判定点驱动 — 无开关: 有持久化点位(mfEntDumps)即自动重打。
//   扫描(F8) → 点卡片左划[patch+持久化] → 存 mfEntDumps_<bid> → 冷启动走这里自动重打。
//   keychain/cloudkit 豁免已退役(v2.57.1 拆除, 样本退役后只剩污染)。
void apEntDumpsApply(void);   // fwd: 定义在采集器区块之后, Boot 前置声明
void mfAppPatchBoot(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        // v2.58.62: 诊断 — 冷启动读 app UD 的 isPro 镜像值, 判定 patch 后写路径是否生效
    // v2.58.63: 修正域 — 注入进程内 standardUserDefaults 才是 app 自己的域;
    //   旧版 initWithSuiteName 读的是 suite 域(app 未用) → 恒 nil 误报"写侧没跑"
    {
        // v2.58.68: 去硬编码(旧版写死单个目标 app 的 key + 前缀计数)
        //   — 诊断改为通用: 扫标准域里含权益语义族的 key, 报数量与 Bool 位快照。
        NSUserDefaults *au = [NSUserDefaults standardUserDefaults];
        NSDictionary *rep = [au dictionaryRepresentation];
        static const char *kDiagWords[] = { "ispro", "entitle", "isvip", "premium", "license",
            "purchas", "subscri", "unlock", "vip" };
        NSMutableArray *hitKeys = [NSMutableArray array];
        for (NSString *k in rep.allKeys) {
            NSString *lk = [k lowercaseString];
            for (int w = 0; w < (int)(sizeof(kDiagWords)/sizeof(kDiagWords[0])); w++)
                if (strstr(lk.UTF8String, kDiagWords[w])) { [hitKeys addObject:k]; break; }
        }
        NSString *snap = @"-";
        for (NSString *k in hitKeys) {
            id v = rep[k];
            if ([v isKindOfClass:[NSNumber class]]) { snap = [NSString stringWithFormat:@"%@=%@", k, v]; break; }
        }
        apLog(@"[AppPatch] [statediag] 权益语义 key=%lu 个 · 首个 Bool 位: %@", (unsigned long)hitKeys.count, snap);
    }
    apEntDumpsApply();
    // v2.58.68: 旧 udseed(写死单目标 app 的解锁位 key)已泛化 —
    //   语义保留(每次启动重锤解锁位, 防 app 启动重置), 数据源改为该 app 自己的
    //   侦查缓存语义 key, 不再内置单 app 特征。
    //   只对"已开💾持久化"的 app 生效(= 用户确认过该 app 走状态型路线), 不主动乱写。
    {
        extern BOOL mfStatePersistIsOn(void);
        extern NSArray *mfStateKeysForUI(void);
        extern long mfStateUnlockApplyKey(NSString *, BOOL);
        if (mfStatePersistIsOn()) {
            NSArray *ks = mfStateKeysForUI();
            NSUInteger nHeavy = 0, nClear = 0;
            for (NSDictionary *d in ks) {
                NSString *k = d[@"key"];
                if (![k isKindOfClass:[NSString class]] || !k.length) continue;
                // 解锁位重锤 + 反向词(存在=锁定)清理 — 与 F9 ⚡ 同一实现, 复用不重写
                if (mfStateUnlockApplyKey(k, YES)) nHeavy++;
                nClear++;
            }
            if (nHeavy)
                apLog(@"[statediag] 启动重锤: %lu/%lu 个语义 key 已复写(app 启动重置免疫)",
                      (unsigned long)nHeavy, (unsigned long)nClear);
        }
    }
    apApplyRules();        // 规则表(text/method 手工高级用法, 判定点主流程不依赖)
    });
}

// ====== v2.58: 判定点持久化(替代规则表 JSON 手编) ======
// 存储格式: prefs mfEntDumps_<bid> = [{img,sym,note,on}] — 点位数据由侦查卡 F8 扫描产出,
// 用户在实验模拟页判定点卡片上左划 [patch] / [持久化开关], 冷启动 Boot 自动重打已开启项。
// 规则表 mfAppPatchRules 仍保留(text/method 手工高级用法), 但判定点主流程不再依赖它。
static NSMutableArray *g_entDumps = nil;
static void apEntDumpsLoad(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        id raw = mfReadPrefObj([NSString stringWithFormat:@"mfEntDumps_%@", apCurBundleID()]);
        if ([raw isKindOfClass:[NSString class]]) {
            NSArray *a = [NSJSONSerialization JSONObjectWithData:[raw dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:nil];
            if ([a isKindOfClass:[NSArray class]]) g_entDumps = [a mutableCopy];
        }
        if (!g_entDumps) g_entDumps = [NSMutableArray new];
        // v2.58.70: 墓碑自愈 — 库里已存在的墓碑点位(用户 ✂ 过但被重扫 merge 复活的)
        //   启动即剔除, 不进重打清单。mf_debug_72: deepslot@11d1398.9 僵尸在库 on=YES
        //   → 双点恒1 → 破坏 CustomerInfo 解析 → mock 腿假死。
        {
            NSArray *tombs2 = apTombstones();
            if (tombs2.count) {
                NSMutableArray *clean2 = [NSMutableArray array];
                for (NSDictionary *d2 in g_entDumps) {
                    NSString *sy2 = d2[@"sym"] ?: @"";
                    if (sy2.length && [tombs2 containsObject:sy2]) {
                        apLog(@"[entdump] ⚰ 墓碑自愈: 剔除 %@ (on=%@, 不再重打)", sy2, d2[@"on"] ?: @0);
                        continue;
                    }
                    [clean2 addObject:d2];
                }
                if (clean2.count != g_entDumps.count) {
                    g_entDumps = clean2;
                    NSData *dd2 = [NSJSONSerialization dataWithJSONObject:g_entDumps options:0 error:nil];
                    if (dd2) mfWritePrefObj([NSString stringWithFormat:@"mfEntDumps_%@", apCurBundleID()],
                                            [[NSString alloc] initWithData:dd2 encoding:NSUTF8StringEncoding]);
                }
            }
        }
        // v2.58.65: 旧库自愈 — sk2ver 判别点是死代码(实机三轮零作用), 从库中剔除
        //   (用户在 2.58.64 前扫入的遗留条目, 不清会继续出现在列表/重打清单里)
        // v2.58.113: ivargate/ivargate+ 一并列入 — 两者均经实测证伪
        //   (mf_debug_100/101/105: 点位 patch 字节全落地, UI 三轮零变化;
        //    读侧点在结构体拷贝函数里, 写侧点不在 HMVipProManager 方法族 /
        //    实际权益源是 SK2 currentEntitlements, 与本地点位无关)。
        NSMutableArray *clean = [NSMutableArray array];
        for (NSDictionary *d in g_entDumps) {
            NSString *sym = d[@"sym"] ?: @"";
            if ([sym hasPrefix:@"sk2ver@"]) continue;
            if ([sym hasPrefix:@"ivargate@"]) continue;
            if ([sym hasPrefix:@"ivargate+@"]) continue;
            [clean addObject:d];
        }
        if (clean.count != g_entDumps.count) {
            g_entDumps = clean;
            apLog(@"[entdump] 自愈: 剔除死代码点位(sk2ver/ivargate/ivargate+) 剩余 %lu 条",
                  (unsigned long)g_entDumps.count);
            NSData *dd = [NSJSONSerialization dataWithJSONObject:g_entDumps options:0 error:nil];
            if (dd) mfWritePrefObj([NSString stringWithFormat:@"mfEntDumps_%@", apCurBundleID()],
                                   [[NSString alloc] initWithData:dd encoding:NSUTF8StringEncoding]);
        }
    });
}
static void apEntDumpsSave(void) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:g_entDumps options:0 error:nil];
    if (d) mfWritePrefObj([NSString stringWithFormat:@"mfEntDumps_%@", apCurBundleID()],
                          [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding]);
}
NSArray *mfAppPatchEntDumps(void) { apEntDumpsLoad(); return g_entDumps; }
// v2.58.61: 会话缓存架构已废(用户定案"你为什么要搞得这么复杂") —
//   侦查→mfAppPatchEntDumpsMerge 入库, 实验/列表 UI 只读持久层。"本次有效"概念删除。
// F8 扫描点位合并进持久存储(去重: img+sym 相同视为同点)
// v2.58.74: 轮次机制 — 卡片"共 N 点"读的是持久库全量, 跨轮 merge 只增不减
//   → mf_debug_75 用户看到 35 点(侦查详情只报 12, 库里是历史累积)。
//   侦查开始清 seen, merge 时置 seen, 结束剔除"本轮未扫出且用户未持久化"的陈旧点;
//   用户 ⚡/💾 过的(on=YES)永不清 — 与墓碑同哲学: 用户意图优先于引擎本轮产出。
static int g_entRoundSeen = 0;
void mfAppPatchEntDumpsBeginRound(void) {
    apEntDumpsLoad();
    g_entRoundSeen = 0;
    for (NSMutableDictionary *m in g_entDumps) m[@"seen"] = @NO;
}
void mfAppPatchEntDumpsEndRound(void) {
    if (g_entRoundSeen == 0) return;   // 本轮零产出(侦查 bail) → 不清, 免误删
    apEntDumpsLoad();
    NSUInteger before = g_entDumps.count;
    NSMutableArray *keep = [NSMutableArray array];
    for (NSDictionary *m in g_entDumps) {
        BOOL seen = [m[@"seen"] boolValue];
        BOOL on = [m[@"on"] boolValue];
        if (!seen && !on) {
            apLog(@"[entdump] ⚰ 陈旧点剔除 %@ (本轮未扫出且未持久化)", m[@"sym"]);
            continue;
        }
        [keep addObject:m];
    }
    if (keep.count != before) {
        g_entDumps = keep;
        apEntDumpsSave();
        apLog(@"[entdump] 库同步: %lu → %lu 条(剔除陈旧 %lu, 保留用户持久化 %lu)",
              (unsigned long)before, (unsigned long)keep.count,
              (unsigned long)(before - keep.count),
              (unsigned long)[[keep filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"on == YES"]] count]);
    }
}
void mfAppPatchEntDumpsMerge(NSArray *newOnes) {
    if (![newOnes isKindOfClass:[NSArray class]]) return;
    apEntDumpsLoad();
    NSArray *tombs = apTombstones();   // v2.58.70: 墓碑点位永不复活
    for (NSDictionary *n in newOnes) {
        if (![n isKindOfClass:[NSDictionary class]]) continue;
        NSString *nsym = n[@"sym"] ?: @"";
        if (nsym.length && [tombs containsObject:nsym]) {
            apLog(@"[entdump] ⚰ 墓碑跳过 %@ (用户已删, 侦查不再入库)", nsym);
            continue;
        }
        BOOL dup = NO;
        for (NSDictionary *o in g_entDumps)
            if ([o[@"img"] isEqualToString:n[@"img"]] && [o[@"sym"] isEqualToString:n[@"sym"]]) { dup = YES; break; }
        if (!dup) {
            NSMutableDictionary *m = [n mutableCopy];
            m[@"on"] = @NO;                       // 新点位默认未开启(用户左划持久化才开)
            m[@"seen"] = @YES;                    // v2.58.74: 本轮扫出
            [g_entDumps addObject:m];
            g_entRoundSeen++;
        } else {
            // v2.58.18: 旧点位补 shape 字段(重扫后分类升级, 不动用户持久化开关)
            // v2.58.30: 同时补 vmaddr/slide — mf_debug_30 定谳: ivarRead@/ivarGetter@
            // 合成 sym 无符号表可查, apSwiftTextPatch 查符号必 miss → "symbol not
            // in XXX" → ⚡空转(2.58.27/28 两轮, 日志零落盘)。定位数据必须随点位存库。
            // v2.58.58: old/new 也要刷新 — 2.58.57 及以前存的是 %08x 值序(执行端按
            // 内存序解析 → 字节倒序 → old 校验 mismatch/新字节错), 本轮起扫描端改
            // mfLeHex 内存序; 旧点位重扫时在此处换代修正。
            for (NSMutableDictionary *m in g_entDumps)
                if ([m[@"img"] isEqualToString:n[@"img"]] && [m[@"sym"] isEqualToString:n[@"sym"]]) {
                    m[@"seen"] = @YES;            // v2.58.74: 本轮重温 → 不算陈旧
                    g_entRoundSeen++;
                    if (n[@"shape"] && !m[@"shape"]) m[@"shape"] = n[@"shape"];
                    if (n[@"vmaddr"] && !m[@"vmaddr"]) m[@"vmaddr"] = n[@"vmaddr"];
                    if (n[@"slide"] && !m[@"slide"]) m[@"slide"] = n[@"slide"];
                    if (n[@"old"]) m[@"old"] = n[@"old"];
                    if (n[@"new"]) m[@"new"] = n[@"new"];
                    break;
                }
        }
    }
    apEntDumpsSave();
}
void mfAppPatchEntDumpSetOn(NSString *sym, BOOL on) {
    apEntDumpsLoad();
    for (NSMutableDictionary *m in g_entDumps)
        if ([m[@"sym"] isEqualToString:sym]) { m[@"on"] = @(on); break; }
    apEntDumpsSave();
}
// v2.58.12: 删除点位 — 左划删除用; 同 sym 去重口径单条删除(扫描 merge 端 img+sym 去重)
// v2.58.70: ✂ 墓碑 — 用户删过的点位, 侦查 merge 不再复活。
//   mf_debug_72 定谳: F10 每次侦查都扫出同族点(11d1398=CustomerInfo 序列化族,
//   非 licensed 真点), 用户在 46 轮 ✂ 删过, 但 72 轮重扫又被 merge 回库 → 双点
//   恒1 破坏 CustomerInfo 解析 → mock 数据到不了 UI → 双因子瘸腿。
//   墓碑按 bid 隔离(prefs key mfTombstones_<bid>), 跨会话持久。
static NSArray *apTombstones(void) {
    id v = mfReadPrefObj([NSString stringWithFormat:@"mfTombstones_%@", apCurBundleID()]);
    return [v isKindOfClass:[NSArray class]] ? v : @[];
}
static void apTombstoneAdd(NSString *sym) {
    NSMutableArray *ts = [apTombstones() mutableCopy] ?: [NSMutableArray array];
    if (![ts containsObject:sym]) [ts addObject:sym];
    mfWritePrefObj([NSString stringWithFormat:@"mfTombstones_%@", apCurBundleID()], ts);
}
// v2.58.77: 墓碑可恢复 — 单向门是设计缺陷(用户: "误删真判定点=永久解不开这个app?")。
//   提供: 计数/全清/单点恢复。删除是用户意图, 但"误删"必须能撤回。
NSUInteger mfAppPatchTombstoneCount(void) { return apTombstones().count; }
void mfAppPatchTombstonesClear(void) {
    mfWritePrefObj([NSString stringWithFormat:@"mfTombstones_%@", apCurBundleID()], nil);
    apLog(@"[entdump] ♻️ 墓碑已清空 — 被删点位可被侦查重新发现");
}
void mfAppPatchTombstoneRemove(NSString *sym) {
    NSMutableArray *ts = [apTombstones() mutableCopy] ?: [NSMutableArray array];
    if ([ts containsObject:sym]) {
        [ts removeObject:sym];
        mfWritePrefObj([NSString stringWithFormat:@"mfTombstones_%@", apCurBundleID()], ts);
        apLog(@"[entdump] ♻️ 墓碑移除 %@ — 下次侦查可重新入库", sym);
    }
}
void mfAppPatchEntDumpDelete(NSString *sym) {
    apEntDumpsLoad();
    for (NSInteger i = (NSInteger)g_entDumps.count - 1; i >= 0; i--)
        if ([g_entDumps[i][@"sym"] isEqualToString:sym]) {
            [g_entDumps removeObjectAtIndex:(NSUInteger)i];
            apLog(@"[entdump] ✂ 删除点位 %@ (已立墓碑, 侦查不再复活)", sym);
            break;
        }
    apTombstoneAdd(sym);   // v2.58.70: 无论库中是否有, 都记墓碑(防 merge 复活)
    apEntDumpsSave();
}
// 冷启动/热触发: 重打所有 on=YES 点位(持久化执行核心)
void apEntDumpsApply(void) {
    apEntDumpsLoad();
    if (!g_entDumps.count) return;
    for (NSDictionary *d in g_entDumps) {
        if (![d[@"on"] boolValue]) continue;
        // v2.58.18: ptr 形态拦截(持久化路径同防 — 指针返回型 patch 会崩)
        if ([d[@"shape"] isEqualToString:@"ptr"]) {
            apLog(@"[entdump] ⛔ %@ shape=ptr 跳过重打", [d[@"sym"] lastPathComponent]);
            continue;
        }
        NSString *err = nil;
        NSData *newBytes = nil;
        if ([d[@"sym"] hasPrefix:@"ivarRead@"]) {
            unsigned rt = 0;
            NSRange dot = [d[@"sym"] rangeOfString:@"." options:NSBackwardsSearch];
            if (dot.location != NSNotFound) rt = (unsigned)[[d[@"sym"] substringFromIndex:dot.location + 1] intValue];
            uint32_t movz = 0x52800020u | rt;
            newBytes = [NSData dataWithBytes:&movz length:4];
        } else if ([d[@"sym"] hasPrefix:@"deepslot@"]) {
            // v2.58.40: F10 深槽装载点 — ldur x<Rt>,[x29,#-imm] → mov x<Rt>,#1
            //   sym 格式 deepslot@0x<off>.<Rt> — MOVZ X<Rt>,#1 = 0xd2800000 | (1<<5) | Rt
            unsigned rt = 9;
            NSRange dot = [d[@"sym"] rangeOfString:@"." options:NSBackwardsSearch];
            if (dot.location != NSNotFound) rt = (unsigned)[[d[@"sym"] substringFromIndex:dot.location + 1] intValue];
            if (rt > 30) rt = 9;    // 容错: 解析失败回落 x9(实测寄存器)
            uint32_t movx = 0xd2800000u | (1u << 5) | rt;
            newBytes = [NSData dataWithBytes:&movx length:4];
        } else if ([d[@"sym"] hasPrefix:@"sk2pro@"] || [d[@"sym"] hasPrefix:@"sk2dat@"]) {
            // v2.58.52→58: SK2 数据源装载点 — ldr → movz xT,#1(记录恒存在, 恒解锁)
            // v2.58.71: sk2dat(B 路)同语义 — sym 格式 sk2dat@0x<off>.<Rt>, 优先用库内 new
            unsigned rt7 = 0;
            NSRange dot7 = [d[@"sym"] rangeOfString:@"." options:NSBackwardsSearch];
            if (dot7.location != NSNotFound) rt7 = (unsigned)[[d[@"sym"] substringFromIndex:dot7.location + 1] intValue];
            if ([d[@"new"] isKindOfClass:[NSString class]] && [d[@"new"] length])
                newBytes = apHexToBytes(d[@"new"]);
            else if (rt7 <= 30)
                newBytes = mfLeHex(0xD2800000u | (1u << 5) | rt7);   // movz x<rt>,#1(内存序)
            else newBytes = apHexToBytes(@"370080d2");   // movz x23,#1 兜底(内存序)
        } else if ([d[@"sym"] hasPrefix:@"sk2get@"]) {
            // v2.58.62: SK2 UI 读侧 getter — ldrb w0,[xN,#0x10] → mov w0,#1
            //   (写侧 refresh 未购买态可能不跑, mf_debug_65 sk2diag=nil 实锤)
            if ([d[@"new"] isKindOfClass:[NSString class]] && [d[@"new"] length])
                newBytes = apHexToBytes(d[@"new"]);
            else newBytes = apHexToBytes(@"20008052");   // mov w0,#1 兜底
        } else if ([d[@"sym"] hasPrefix:@"sk2br@"]) {
            // v2.58.78: 分支粒度判定点 — Pro 门的"逃逸分支"→ NOP(fall through 到汇聚点)。
            //   与函数头短路(sk2pro/sk2get)不同: 不改函数入口, 只改门的分支决策,
            //   保留函数完整逻辑(多返回路径大函数安全)。new 存库内字节。
            if ([d[@"new"] isKindOfClass:[NSString class]] && [d[@"new"] length])
                newBytes = apHexToBytes(d[@"new"]);
            else newBytes = apHexToBytes(@"1f2003d5");   // nop 兜底
        } else newBytes = apHexToBytes(@"20008052c0035fd6");   // mov w0,#1; ret
        // v2.58.84 (mf_debug_86 定谳): 序言形态拦截。
        //   F8v2 语义锚定候选点位上入库的是"函数序言"(sub sp,sp,#N / stp X,X,[sp,#-N]! / pacibsp),
        //   而执行器把序言整体替换成 4 字节 mov w0,#1 — 函数随后照常执行 stp x28,x27,[sp,#8],
        //   此时栈帧并未建立 → 写进调用者栈帧; 且返回值在函数尾部被真实逻辑覆盖。
        //   结果: 既不解锁(返回值被覆盖), 又毁栈(mf_debug_85 四序言点即此形态, 全部空转)。
        //   序言点位的语义不可知(可能是 void / 多返回值), 4 字节无法安全表达 → 拒绝执行。
        {
            NSData *oldChk = ([d[@"old"] isKindOfClass:[NSString class]] && [d[@"old"] length])
                             ? apHexToBytes(d[@"old"]) : nil;
            if (oldChk.length >= 4) {
                uint32_t o0 = 0; [oldChk getBytes:&o0 length:4];
                BOOL isPrologue = ((o0 & 0xFFC003FF) == 0xD10003FF && ((o0 >> 10) & 0xFFF)) ||
                                  ((o0 & 0x7FC00000) == 0x29800000 && ((o0 >> 5) & 0x1F) == 31) ||
                                  (o0 == 0xD503237F);
                if (isPrologue) {
                    apLog(@"[entdump] ⛔ %@ 序言形态(%08x) 拒绝 patch — 4 字节无法安全表达(会毁栈且返回值被覆盖)",
                          [d[@"sym"] lastPathComponent], o0);
                    g_apProPhit++;
                    continue;
                }
            }
        }
        // v2.58.52: 点位带 old 字段时校验原字节(指令漂移自检, sk2pro/sk2ver 专用)
        NSData *oldBytes = ([d[@"old"] isKindOfClass:[NSString class]] && [d[@"old"] length]) ? apHexToBytes(d[@"old"]) : nil;
        if (apSwiftTextPatchDump(d, oldBytes, newBytes, &err)) {
            g_apHits++;
            apLog(@"[entdump] ✓ %@ 持久化 patch 重打", [d[@"sym"] lastPathComponent]);
        } else apLog(@"[entdump] ✗ %@: %@", d[@"sym"], err);
    }
}
long mfAppPatchEntDumpCount(void) { apEntDumpsLoad(); return g_entDumps.count; }

// v2.21 教训: 内存首拍在 ctor 才拍, 而 TrollFools 注入的补丁 dylib
// 初始化更早 — patch 在基线之前就打完了, 内存 diff 永远是 0 (假阴性)
// 破法: 主二进制文件 = 原始字节 (主程序 vmaddr偏移==文件偏移),
// 文件区段 vs 内存同偏移对照, 何时打的 patch 都能现形
// ==================================================================
BOOL mfAppPatchCollIsOn(void) { return mfPrefBool(apPrefKey(@"mfAppPatchCollector"), NO); }

static dispatch_source_t g_collTimer = nil;
static NSData *g_collBase = nil;      // 内存首拍 (__TEXT 全量, 第二层)
static uintptr_t g_collBaseAddr = 0;
static NSUInteger g_collBaseLen = 0;

// 磁盘基线区: {off(文件/vm偏移), len, fileBytes}
typedef struct { uint64_t off; uint64_t len; NSData *fileBytes; } ApWatchRegion;
static ApWatchRegion g_watch[8];
static int g_watchN = 0;

static NSData *apReadFileRange(NSString *path, uint64_t off, uint64_t len) {
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) return nil;
    NSData *d = nil;
    @try {
        [fh seekToFileOffset:(unsigned long long)off];
        NSData *raw = [fh readDataOfLength:(NSUInteger)len];
        if (raw.length == len) d = raw;
    } @catch (NSException *e) { d = nil; }
    @finally { [fh closeFile]; }
    return d;
}

static NSData *apReadMemRange(uintptr_t addr, NSUInteger len) {
    vm_offset_t data = 0; mach_msg_type_number_t size = 0;
    kern_return_t kr = vm_read(mach_task_self(), addr, len, &data, &size);
    if (kr != KERN_SUCCESS || size != len) { if (data) vm_deallocate(mach_task_self(), data, size); return nil; }
    NSData *d = [NSData dataWithBytes:(void*)data length:size];
    vm_deallocate(mach_task_self(), data, size);
    return d;
}

static void apCaptureToJSON(NSArray *diffs, NSString *source) {
    if (!diffs.count) return;
    g_apCollHits += diffs.count;
    NSMutableDictionary *rec = [NSMutableDictionary new];
    rec[@"bid"] = apCurBundleID(); rec[@"ver"] = apCurVersion();
    rec[@"captured"] = [NSDate date]; rec[@"source"] = source;
    rec[@"patches"] = diffs;
    NSString *path = @"/var/mobile/Documents/mf_patch_capture.json";
    NSArray *old = [NSJSONSerialization JSONObjectWithData:[[NSFileManager defaultManager] contentsAtPath:path] options:0 error:nil] ?: @[];
    NSMutableArray *all = [old mutableCopy] ?: [NSMutableArray new];
    [all addObject:rec];
    NSData *out = [NSJSONSerialization dataWithJSONObject:all options:NSJSONWritingPrettyPrinted error:nil];
    [out writeToFile:path atomically:YES];
    NSString *firstOff = diffs[0][@"off"] ?: @"?";
    apLog(@"[采集] ✓ %lu 处 (%@, 首址 %@) → mf_patch_capture.json", (unsigned long)diffs.count, source, firstOff);
}

static NSArray *apDiffBytes(const unsigned char *a, const unsigned char *b, NSUInteger len) {
    NSMutableArray *diffs = [NSMutableArray new];
    NSUInteger i = 0;
    while (i < len) {
        if (a[i] != b[i]) {
            NSUInteger s = i;
            while (i < len && a[i] != b[i]) i++;
            if (diffs.count < 64) {
                [diffs addObject:@{@"off": [NSString stringWithFormat:@"0x%lx", (unsigned long)s],
                                   @"old": apBytesToHex(a + s, i - s),
                                   @"new": apBytesToHex(b + s, i - s)}];
            }
        } else i++;
    }
    return diffs;
}

void apInstallCollectors(void) {
    if (g_apCollInstalled) return;
    if (!mfAppPatchCollIsOn()) return;
    g_collBaseAddr = apMainImageBase();
    if (!g_collBaseAddr) return;

    // 主程序磁盘路径
    const struct mach_header_64 *mh = (const struct mach_header_64*)g_collBaseAddr;
    NSString *diskPath = nil;
    uint64_t textFileLen = 0;
    uint8_t *p = (uint8_t*)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command*)p;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64*)p;
            if (strncmp(seg->segname, "__TEXT", 16) == 0) textFileLen = seg->filesize;
        }
        p += lc->cmdsize;
    }
    uint32_t icount = _dyld_image_count();
    for (uint32_t i = 0; i < icount; i++) {
        if ((uintptr_t)_dyld_get_image_header(i) == g_collBaseAddr) {
            const char *nm = _dyld_get_image_name(i);
            if (nm) diskPath = [NSString stringWithUTF8String:nm];
            break;
        }
    }
    apLog(@"[采集] main=0x%lx disk=%@ __TEXT.filelen=0x%llx", (unsigned long)g_collBaseAddr, diskPath ?: @"?", textFileLen);

    // 观察区: prefs mfAppPatchWatch 覆盖, 默认 = v2.20 实测抓到的 vm_protect 目标
    NSString *watch = mfReadPrefObj(@"mfAppPatchWatch") ?: @"0x2c8c000:0x108";
    if (![watch isKindOfClass:[NSString class]]) watch = @"0x2c8c000:0x108";
    NSArray *parts = [watch componentsSeparatedByString:@","];
    for (NSString *part in parts) {
        if (g_watchN >= 8) break;
        NSArray *kv = [part componentsSeparatedByString:@":"];
        if (kv.count != 2) continue;
        unsigned long long off = strtoull([kv[0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]].UTF8String, NULL, 16);
        unsigned long long len = strtoull([kv[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]].UTF8String, NULL, 16);
        if (!len || len > 0x100000 || off >= textFileLen || off + len > textFileLen) continue;
        NSData *fb = diskPath ? apReadFileRange(diskPath, off, len) : nil;
        if (!fb) { apLog(@"[采集] 区间 0x%llx 读盘失败, 跳过", off); continue; }
        g_watch[g_watchN].off = off; g_watch[g_watchN].len = len; g_watch[g_watchN].fileBytes = fb;
        g_watchN++;
        // 装载即对照: patch 若在基线前已打, 此刻现形
        NSData *mem = apReadMemRange(g_collBaseAddr + off, (NSUInteger)len);
        if (!mem) { apLog(@"[采集] 区间 0x%llx 内存读失败", off); continue; }
        if (![mem isEqualToData:fb]) {
            NSArray *diffs = apDiffBytes(fb.bytes, mem.bytes, (NSUInteger)len);
            apLog(@"[采集] 区间 0x%llx 装载即有差异 (patch 先于基线)!", off);
            apCaptureToJSON(diffs, @"file-baseline@install");
        } else {
            apLog(@"[采集] 区间 0x%llx 当前与磁盘一致, 持续监视", off);
        }
    }

    // 第二层: __TEXT 全量内存首拍 (捕捉基线后的任何写入)
    if (textFileLen && textFileLen <= 96ull*1024*1024) {
        g_collBaseLen = (NSUInteger)textFileLen;
        @try { g_collBase = [NSData dataWithBytes:(void*)g_collBaseAddr length:g_collBaseLen]; }
        @catch (NSException *e) { g_collBase = nil; }
        if (g_collBase) apLog(@"[采集] 内存首拍 __TEXT (%lu B) — 2s 周期", (unsigned long)g_collBaseLen);
    }

    g_collTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(g_collTimer, dispatch_walltime(NULL, 0), 2.0 * NSEC_PER_SEC, 0.5 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(g_collTimer, ^{
        @autoreleasepool {
            // 层1: 观察区 (文件基线)
            for (int i = 0; i < g_watchN; i++) {
                NSData *mem = apReadMemRange(g_collBaseAddr + (NSUInteger)g_watch[i].off, (NSUInteger)g_watch[i].len);
                if (!mem) continue;
                if (![mem isEqualToData:g_watch[i].fileBytes]) {
                    NSArray *diffs = apDiffBytes(g_watch[i].fileBytes.bytes, mem.bytes, (NSUInteger)g_watch[i].len);
                    apCaptureToJSON(diffs, @"file-baseline@poll");
                    g_watch[i].fileBytes = mem; // 更新为当前, 避免重复报
                }
            }
            // 层2: __TEXT 全量 (内存基线)
            if (g_collBase) {
                NSData *now = nil;
                @try { now = [NSData dataWithBytes:(void*)g_collBaseAddr length:g_collBaseLen]; }
                @catch (NSException *e) { return; }
                if (![now isEqualToData:g_collBase]) {
                    NSArray *diffs = apDiffBytes(g_collBase.bytes, now.bytes, g_collBaseLen);
                    apCaptureToJSON(diffs, @"mem-baseline@poll");
                    g_collBase = now;
                }
            }
        }
    });
    dispatch_resume(g_collTimer);
    g_apCollInstalled = YES;
}

// ====== 面板交互 API ======
NSString *mfAppPatchRulesJSON(void) {
    id v = mfReadPrefObj(@"mfAppPatchRules");
    if ([v isKindOfClass:[NSString class]]) return v;
    // v2.58.69: 预置规则模板已清空 — 旧版预置单 app 的 bid/版本/指令偏移(泄漏残留),
    //   且判定点主流程早已不依赖规则表(apEntDumps 驱动)。模板只留空数组 + 格式示例。
    return @"[]";
}
void mfAppPatchSetRulesJSON(NSString *json) {
    NSData *d = [json dataUsingEncoding:NSUTF8StringEncoding];
    id obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![obj isKindOfClass:[NSArray class]]) return;
    mfWritePrefObj(@"mfAppPatchRules", json);
}
void mfAppPatchApplyNow(void) {
    dispatch_async(dispatch_get_main_queue(), ^{ apApplyRules(); });
}
NSArray *mfAppPatchLogLines(void) {
    @synchronized (g_apLog) { return [g_apLog copy] ?: @[]; }
}
long mfAppPatchCollHits(void) { return g_apCollHits; }

// ====== 面板 UI ======
// MFPanelCtrl 定义在 MFPanel.m — 此处最小前向声明让 category 可编译, 运行时指向真类
@interface MFPanelCtrl : NSObject @end
@interface MFPanelCtrl (AppPatch)
- (void)mfAPSwitchChanged:(UISwitch *)sw;
- (void)mfAPCollSwitchChanged:(UISwitch *)sw;
- (void)mfAPShowRulesEditor;
- (void)mfAPRulesEditorSave;
- (void)mfAPApplyNow;
- (void)mfAPShowLog;
@end

// v2.58: 判定点操作方法在独立 category(列表类需文件作用域)
@interface MFPanelCtrl (AppPatchEnt)
- (void)mfAPShowEntDumps;
- (void)mfAPRestoreTombstones:(UIButton *)btn;   // v2.58.77: 清墓碑(误删真点的退路)
- (void)mfAPShowSk2List;   // v2.58.52: SK2 判别点过滤列表(与 F8v2 点位分家)
- (void)mfAPEntPatchNow:(NSString *)sym;
- (void)mfAPEntSetOn:(NSString *)sym on:(BOOL)on;
- (void)mfAPKeychainStub;
- (void)mfAPEntDelete:(NSString *)sym;   // v2.58.12: 左划删除 — 假点位手动清理解
@end

static UITextView *g_apEditor = nil;
@implementation MFPanelCtrl (AppPatch)
- (void)mfAPSwitchChanged:(UISwitch *)sw {
    mfSetBoolPref(apPrefKey(@"mfAppPatchEnabled"), sw.on);
    if (sw.on) mfAppPatchBoot();
    mfToast(sw.on ? @"引擎已开(本 app), 冷启动生效" : @"引擎已关(本 app)");
}
- (void)mfAPCollSwitchChanged:(UISwitch *)sw {
    mfSetBoolPref(apPrefKey(@"mfAppPatchCollector"), sw.on);
    if (sw.on) { apInstallCollectors(); mfToast(@"采集器已装 (被动快照模式)"); }
    else mfToast(@"开关已存, 重启 app 卸载");
}
- (void)mfAPApplyNow {
    mfAppPatchApplyNow();
    mfToast(@"已触发");
}
- (void)mfAPShowRulesEditor {
    UIView *page = mfMakePage(@"📜 规则表编辑", YES);
    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(12, 54, g_mfCardW - 24, g_mfCardH - 200)];
    tv.text = mfAppPatchRulesJSON();
    tv.font = [UIFont fontWithName:@"Menlo" size:11];
    tv.autocorrectionType = UITextAutocorrectionTypeNo;
    tv.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tv.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    tv.layer.cornerRadius = 10;
    [page addSubview:tv];
    g_apEditor = tv;
    mfAttachKbBar(tv);
    UIButton *save = [UIButton buttonWithType:UIButtonTypeSystem];
    save.frame = CGRectMake(12, g_mfCardH - 136, (g_mfCardW - 32) / 2, 42);
    [save setTitle:@"💾 保存" forState:UIControlStateNormal];
    [save addTarget:g_mfCtrl action:@selector(mfAPRulesEditorSave) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:save];
    UIButton *apply = [UIButton buttonWithType:UIButtonTypeSystem];
    apply.frame = CGRectMake(12 + (g_mfCardW - 32) / 2 + 8, g_mfCardH - 136, (g_mfCardW - 32) / 2, 42);
    [apply setTitle:@"⚡ 立即应用" forState:UIControlStateNormal];
    [apply addTarget:g_mfCtrl action:@selector(mfAPApplyNow) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:apply];
    mfPushPage(page);
}
- (void)mfAPRulesEditorSave {
    if (!g_apEditor) return;
    mfAppPatchSetRulesJSON(g_apEditor.text);
    mfToast(@"已保存");
}
- (void)mfAPShowLog {
    UIView *page = mfMakePage(@"📋 AppPatch 日志", YES);
    NSArray *lines = mfAppPatchLogLines();
    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(12, 54, g_mfCardW - 24, g_mfCardH - 120)];
    tv.text = lines.count ? [lines componentsJoinedByString:@"\n"] : @"(空)";
    tv.font = [UIFont fontWithName:@"Menlo" size:10];
    tv.editable = NO;
    [page addSubview:tv];
    mfPushPage(page);
}
// ====== v2.58: 判定点卡片页(productID 捕获列表同款: UITableView + 左划) ======
@end

// 独立列表类(对标 MFScanList): items = mfAppPatchEntDumps() 的 {img,sym,vmaddr,on}
// (v2.58 修复: 独立 @implementation 不能嵌在 category 内 — 移到文件作用域)
@interface MFAPEntList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *items;
@end
@implementation MFAPEntList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return self.items.count; }
- (CGFloat)tableView:(UITableView *)tv heightForRowAtIndexPath:(NSIndexPath *)ip { return 64; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *idt = @"mfEntRow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:idt];
    if (!c) {
        c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:idt];
        c.backgroundColor = UIColor.clearColor;
        c.selectionStyle = UITableViewCellSelectionStyleNone;
        UILabel *fn = [UILabel new]; fn.tag = 201;
        fn.font = [UIFont fontWithName:@"Menlo" size:11]; fn.textColor = [UIColor labelColor];
        fn.lineBreakMode = NSLineBreakByTruncatingMiddle;
        UILabel *loc = [UILabel new]; loc.tag = 202;
        loc.font = [UIFont fontWithName:@"Menlo" size:9.5]; loc.textColor = [UIColor secondaryLabelColor];
        loc.lineBreakMode = NSLineBreakByTruncatingMiddle;
        UILabel *st = [UILabel new]; st.tag = 203;
        st.font = [UIFont systemFontOfSize:10]; st.textColor = [UIColor tertiaryLabelColor];
        [c.contentView addSubview:fn]; [c.contentView addSubview:loc]; [c.contentView addSubview:st];
    }
    NSDictionary *d = self.items[ip.row];
    CGFloat w = g_mfCardW - 32;
    UILabel *fn = [c.contentView viewWithTag:201], *loc = [c.contentView viewWithTag:202], *st = [c.contentView viewWithTag:203];
    fn.frame = CGRectMake(16, 5, w - 16, 17);
    loc.frame = CGRectMake(16, 22, w - 16, 15);
    st.frame = CGRectMake(16, 39, w - 16, 15);
    // 函数名显示: mangled 尾段人类可读化(_$s 前缀剥掉, 取后 44 字符)
    NSString *sym = d[@"sym"] ?: @"";
    NSString *img = d[@"img"] ?: @"";
    NSString *pretty = sym;
    if ([sym hasPrefix:@"_$s"]) {
        NSArray *parts = [sym componentsSeparatedByString:[img length] ? img : @"9NoMatchFramework"];
        pretty = parts.count > 1 ? [NSString stringWithFormat:@"SDK%@", parts.lastObject] : sym;
    }
    fn.text = pretty.length > 52 ? [NSString stringWithFormat:@"…%@", [pretty substringFromIndex:pretty.length - 52]] : pretty;
    loc.text = [NSString stringWithFormat:@"%@:%@+%@", d[@"img"] ?: @"?", [d[@"vmaddr"] stringValue], @([d[@"slide"] longValue])];
    BOOL on = [d[@"on"] boolValue];
    // v2.58.18: 形态标记 — ptr(指针返回)patch 必崩, 红🔻警示; bool 可安全⚡
    NSString *shape = d[@"shape"] ?: @"";
    if ([shape isEqualToString:@"ptr"]) {
        st.text = @"🔻ptr 禁patch — 指针返回会崩";
        st.textColor = [UIColor systemRedColor];
    } else if ([shape isEqualToString:@"bool"]) {
        st.text = on ? @"💾✓ Bool判定 — 冷启动自动重打" : @"✓ Bool判定 — 左划⚡(即持久)";
        st.textColor = on ? [UIColor systemGreenColor] : [UIColor systemTealColor];
    } else {
        st.text = on ? @"💾 已持久化 — 冷启动自动重打" : @"未开启 — 左划⚡patch";
        st.textColor = on ? [UIColor systemGreenColor] : [UIColor tertiaryLabelColor];
    }
    return c;
}
// 左划: ⚡立即patch(橙) / 💾持久化开关(绿/灰)
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSDictionary *d = self.items[ip.row];
    NSString *sym = d[@"sym"] ?: @"";
    BOOL on = [d[@"on"] boolValue];
    UIContextualAction *patch = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:on ? @"⚡重打" : @"⚡patch" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [(id)g_mfCtrl mfAPEntPatchNow:sym];
            done(YES);
        }];
    patch.backgroundColor = [UIColor systemOrangeColor];
    // v2.58.31: 💾取消 = 回滚(还原 patch 状态 + off) — 与 F9 卡片「patch 即持久化/
    // 取消即回滚」同交互。旧设计 💾是独立开关(⚡patch 不持久化)被用户否掉:
    // "patch 了还要再点一次持久化, 重启就丢" — 2.58.30 全链打通后无意义。
    UIContextualAction *persist = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:on ? @"💾回滚" : @"💾patch" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [(id)g_mfCtrl mfAPEntSetOn:sym on:!on];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [tv reloadData];
            });
            done(YES);
        }];
    persist.backgroundColor = on ? [UIColor systemGrayColor] : [UIColor systemGreenColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[patch, persist]];
}
// v2.58.12: 左划删除(trailing=⚡patch/💾持久, leading=删除 — 分开防误触)
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv leadingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSDictionary *d = self.items[ip.row];
    NSString *sym = d[@"sym"] ?: @"";
    UIContextualAction *del = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleDestructive
        title:@"删除" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [(id)g_mfCtrl mfAPEntDelete:sym];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [tv reloadData];
            });
            done(YES);
        }];
    del.backgroundColor = [UIColor systemRedColor];
    UISwipeActionsConfiguration *lead = [UISwipeActionsConfiguration configurationWithActions:@[del]];
    lead.performsFirstActionWithFullSwipe = NO;   // 防全划误删
    return lead;
}
@end

// category 续: 判定点操作方法(列表类之后重新开)
@implementation MFPanelCtrl (AppPatchEnt)
static MFAPEntList *g_apEntList = nil;
// v2.58.77: 墓碑恢复 — 单向门是缺陷(用户: "误删真点=永久解不开这个 app?")。
//   删除是用户意图要尊重, 但误删必须能撤回: 清空墓碑后, 下次侦查可重新发现这些点。
// v2.58.78: 交互改页内两次点击确认 — 用户指"系统弹窗和插件风格太割裂"(插件是
//   bottom-sheet 页内交互, 系统 alert 是另一种模态, 视觉/手感都不连贯)。
- (void)mfAPRestoreTombstones:(UIButton *)btn {
    NSUInteger n = mfAppPatchTombstoneCount();
    if (!n) { mfToast(@"无已删点位"); return; }
    if (![objc_getAssociatedObject(btn, "mfArmRestore") boolValue]) {
        objc_setAssociatedObject(btn, "mfArmRestore", @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [btn setTitle:[NSString stringWithFormat:@"⚠️ 再点一次确认清除 %lu 个墓碑", (unsigned long)n]
             forState:UIControlStateNormal];
        btn.backgroundColor = [UIColor systemRedColor];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if ([objc_getAssociatedObject(btn, "mfArmRestore") boolValue]) {
                objc_setAssociatedObject(btn, "mfArmRestore", @NO, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                NSUInteger m = mfAppPatchTombstoneCount();
                [btn setTitle:(m ? [NSString stringWithFormat:@"♻️ 恢复被删点位（清墓碑 %lu 个）", (unsigned long)m]
                                  : @"♻️ 无已删点位") forState:UIControlStateNormal];
                btn.backgroundColor = m ? [UIColor systemOrangeColor] : [UIColor tertiarySystemFillColor];
            }
        });
        return;
    }
    objc_setAssociatedObject(btn, "mfArmRestore", @NO, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    mfAppPatchTombstonesClear();
    [btn setTitle:@"♻️ 已清 — 重进侦查页可重新发现" forState:UIControlStateNormal];
    btn.backgroundColor = [UIColor systemGreenColor];
    mfToast(@"墓碑已清 — 重进侦查页即可重新发现");
}
- (void)mfAPShowEntDumps {
    UIView *page = mfMakePage(@"🎯 判定点", YES);
    g_apEntList = [[MFAPEntList alloc] init];
    // v2.58.61: UI 只读持久层(用户定案: 侦查→入库→卡片按类型显示, 会话缓存概念废除)
    NSArray *rawItems = mfAppPatchEntDumps();
    if (!rawItems.count) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 60, g_mfCardW - 32, 60)];
        e.text = @"暂无点位\n先到「扫描购买」页跑侦查卡";
        e.numberOfLines = 0;
        e.textAlignment = NSTextAlignmentCenter;
        e.font = [UIFont systemFontOfSize:12];
        e.textColor = [UIColor secondaryLabelColor];
        [page addSubview:e];
        mfPushPage(page);
        return;
    }
    // v2.58.52: 支持 shape 过滤(通过 associatedObject 传入) — SK2 卡片只列 sk2ver/sk2pro,
    //   不再与 F8v2 fixups 点混排(用户: "判定点串行了? 两个卡片都是 17 个")
    NSString *shapeFilter = objc_getAssociatedObject(self, "mfAPShapeFilter");
    if (shapeFilter.length) {
        rawItems = [rawItems filteredArrayUsingPredicate:
            [NSPredicate predicateWithFormat:@"shape IN %@", [shapeFilter componentsSeparatedByString:@"|"]]];
    }
    // v2.58.27: 按 score 降序显示 — 旧序=插入序(F8v2 旧候选堆在前), mf_debug_26 实锤
    // 8 个 ivarBoolGetter(score=94, 真判定层)排在第 13+ 位被埋, 用户惯性⚡旧 12 个全空转
    NSArray *sorted = [rawItems sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        int d = [b[@"score"] intValue] - [a[@"score"] intValue];
        if (d) return d < 0 ? NSOrderedDescending : NSOrderedAscending;
        return NSOrderedSame;
    }];
    g_apEntList.items = sorted;
    UITableView *tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 46, g_mfCardW, g_mfCardH - 46)
                                                    style:UITableViewStylePlain];
    tv.dataSource = g_apEntList;
    tv.delegate = g_apEntList;
    tv.rowHeight = 64;
    tv.separatorStyle = UITableViewCellSeparatorStyleNone;
    [page addSubview:tv];
    mfPushPage(page);
}
// v2.58.52: SK2 判别点专属列表 — 与 F8v2 点位分家(用户: "判定点串行了")
// v2.58.54: 含 sk2pro(isPro 写入点) — 两类 SK2 点都在这张卡
- (void)mfAPShowSk2List {
    objc_setAssociatedObject(self, "mfAPShapeFilter", @"sk2pro|sk2get", OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [self mfAPShowEntDumps];
    objc_setAssociatedObject(self, "mfAPShapeFilter", nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}
- (void)mfAPEntPatchNow:(NSString *)sym {
    // 立即单点 patch: 从 entDumps 找该 sym 打 mov w0,#1; ret
    // v2.58.28: ivarRead@ 前缀 = ldrb 指令点(mf_debug_27 实锤: @Observable getter
    // patch 头跳过 registrar.access → SwiftUI 崩) — 单指令 ldrb w<Rt> → mov w<Rt>,#1
    for (NSDictionary *d in mfAppPatchEntDumps()) {
        if (![d[@"sym"] isEqualToString:sym]) continue;
        NSString *shape = d[@"shape"] ?: @"";
        if ([shape isEqualToString:@"ptr"]) {
            mfToast(@"⛔ 指针型函数 — patch 会崩, 已拦截");
            apLog(@"[entdump] ⛔ %@ 形态=ptr(指针返回) patch 拦截", sym);
            return;
        }
        NSString *err = nil;
        NSData *newBytes = nil;
        if ([sym hasPrefix:@"ivarRead@"]) {
            // sym 格式 ivarRead@0x<off>.<Rt> — MOVZ w<Rt>,#1 = 0x52800000 | (1<<5) | Rt
            unsigned rt = 0;
            NSRange dot = [sym rangeOfString:@"." options:NSBackwardsSearch];
            if (dot.location != NSNotFound) rt = (unsigned)[[sym substringFromIndex:dot.location + 1] intValue];
            uint32_t movz = 0x52800020u | rt;   // (imm16=1)<<5 | Rd
            newBytes = [NSData dataWithBytes:&movz length:4];
        } else if ([sym hasPrefix:@"deepslot@"]) {
            // v2.58.40: F10 深槽装载点 — ldur x<Rt>,[x29,#-imm] → mov x<Rt>,#1
            //   sym 格式 deepslot@0x<off>.<Rt> — MOVZ X<Rt>,#1 = 0xd2800000 | (1<<5) | Rt
            unsigned rt = 9;
            NSRange dot = [sym rangeOfString:@"." options:NSBackwardsSearch];
            if (dot.location != NSNotFound) rt = (unsigned)[[sym substringFromIndex:dot.location + 1] intValue];
            if (rt > 30) rt = 9;
            uint32_t movx = 0xd2800000u | (1u << 5) | rt;
            newBytes = [NSData dataWithBytes:&movx length:4];
        } else if ([sym hasPrefix:@"sk2pro@"] || [sym hasPrefix:@"sk2dat@"]) {
            // v2.58.52→58: SK2 数据源装载点 — ldr → movz xT,#1(记录恒存在, 恒解锁)
            // v2.58.71: sk2dat(B 路)同语义 — sym 格式 sk2dat@0x<off>.<Rt>, 优先用库内 new
            unsigned rt8 = 0;
            NSRange dot8 = [sym rangeOfString:@"." options:NSBackwardsSearch];
            if (dot8.location != NSNotFound) rt8 = (unsigned)[[sym substringFromIndex:dot8.location + 1] intValue];
            if ([d[@"new"] isKindOfClass:[NSString class]] && [d[@"new"] length])
                newBytes = apHexToBytes(d[@"new"]);
            else if (rt8 <= 30)
                newBytes = mfLeHex(0xD2800000u | (1u << 5) | rt8);   // movz x<rt>,#1(内存序)
            else newBytes = apHexToBytes(@"370080d2");   // movz x23,#1 兜底(内存序)
        } else if ([sym hasPrefix:@"sk2get@"]) {
            // v2.58.62: SK2 UI 读侧 getter — ldrb w0,[xN,#0x10] → mov w0,#1
            if ([d[@"new"] isKindOfClass:[NSString class]] && [d[@"new"] length])
                newBytes = apHexToBytes(d[@"new"]);
            else newBytes = apHexToBytes(@"20008052");   // mov w0,#1 兜底
        } else if ([sym hasPrefix:@"sk2br@"]) {
            // v2.58.78: 分支粒度 — Pro 门逃逸分支 NOP(不改函数头, 保留完整逻辑)
            if ([d[@"new"] isKindOfClass:[NSString class]] && [d[@"new"] length])
                newBytes = apHexToBytes(d[@"new"]);
            else newBytes = apHexToBytes(@"1f2003d5");   // nop 兜底
        } else {
            newBytes = apHexToBytes(@"20008052c0035fd6");   // mov w0,#1; ret
        }
        // v2.58.52: 点位带 old 字段时校验原字节(指令漂移自检)
        NSData *oldBytes = ([d[@"old"] isKindOfClass:[NSString class]] && [d[@"old"] length]) ? apHexToBytes(d[@"old"]) : nil;
        // v2.58.85 (mf_debug_87 定谳): 序言形态拦截必须在 ⚡ 立即路径也有 —
        //   v2.58.84 只加在持久化重打路径(apEntDumpsApply), 导致 ⚡ 仍能打穿
        //   4 个序言点(日志实测 pre=d10343ff want=52800020 仍出现)。
        //   序言被 4 字节 mov w0,#1 整体替换后无 ret → 函数继续执行 stp x28,x27,[sp,#8],
        //   栈帧未建立 ⇒ 写进调用者栈帧(毁栈), 且返回值被函数尾部真实逻辑覆盖 ⇒ 双重有害。
        if (oldBytes.length >= 4) {
            uint32_t o0 = 0; [oldBytes getBytes:&o0 length:4];
            BOOL isPrologue = ((o0 & 0xFFC003FF) == 0xD10003FF && ((o0 >> 10) & 0xFFF)) ||
                              ((o0 & 0x7FC00000) == 0x29800000 && ((o0 >> 5) & 0x1F) == 31) ||
                              (o0 == 0xD503237F);
            if (isPrologue) {
                apLog(@"[entdump] ⛔ %@ 序言形态(%08x) 拒绝 patch — 4 字节无法安全表达(毁栈+返回值被覆盖)", sym, o0);
                mfToast(@"⛔ 该点是函数序言 — 无法安全 patch（会毁栈）");
                return;
            }
        }
        if (apSwiftTextPatchDump(d, oldBytes, newBytes, &err)) {
            g_apHits++;
            // v2.58.31: ⚡即持久化 — 与 F9 卡片交互对齐(用户定谳: "patch 了还要再点
            // 一次持久化, 重启就丢" 的双开关设计不要)。⚡成功自动 on, 冷启动重打。
            mfAppPatchEntDumpSetOn(sym, YES);
            apLog(@"[entdump] ⚡ %@ 立即 patch OK + 已持久化", sym);
            mfToast(@"⚡ 已 patch · 冷启动自动重打");
        } else mfToast(err ?: @"patch 失败");
        return;
    }
    mfToast(@"点位不存在(重扫一次)");
}
- (void)mfAPEntSetOn:(NSString *)sym on:(BOOL)on {
    mfAppPatchEntDumpSetOn(sym, on);
    mfToast(on ? @"💾 已持久化 — 冷启动自动重打" : @"已回滚 — 冷启动不再重打");
}
// v2.58.12: 左划删除 — 误扫/假点位清理解
- (void)mfAPEntDelete:(NSString *)sym {
    extern void mfAppPatchEntDumpDelete(NSString *);
    mfAppPatchEntDumpDelete(sym);
    mfToast(@"✂ 已删除点位");
}
@end

// ====== 实验模拟页嵌入块 (由 MFPanel.m 的 mfShowLabPage 调用) ======
// v2.58.24: F9 持久化状态显示(MFStateUnlock.m 导出)
extern BOOL mfStatePersistIsOn(void);

void mfAppPatchSectionInLabPage(UIView *page, CGFloat *yio) {
    CGFloat y = *yio;
    UILabel *grp = [[UILabel alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 20)];
    grp.text = @"AppPatch 判定点引擎";
    grp.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    grp.textColor = [UIColor secondaryLabelColor];
    [page addSubview:grp];
    y += 24;
    // ====== v2.58 重构(用户六点清单): 引擎开关退役 — 有持久化点位(mfEntDumps)冷启动自动重打;
    //   采集器迁观察模块(MFCompatPatcher 同路); 规则表保留为 text/method 手工高级用法。 ======
    // v2.58.67: F9 卡条件显示 — 实测(非状态型 app): 无语义 key 时
    //   (0 语义 key)也一直显示 F9 卡 = 噪声; 用户问"这个 F9 卡片怎么回事"。
    //   判据同主卡: 有语义 key(侦查确认为状态型)才显示。
    {
        extern NSArray *mfStateKeysForUI(void);
        NSArray *f9ks = mfStateKeysForUI();
        BOOL f9stateType = [f9ks isKindOfClass:[NSArray class]] && f9ks.count > 0;
        if (f9stateType) {
            UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 52)];
            bar.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
            bar.layer.cornerRadius = 10;
            UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(12, 5, g_mfCardW - 46, 22)];
            l.text = @"🔓 F9 状态解锁(判定在 plist)";
            l.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
            [bar addSubview:l];
            UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(12, 27, g_mfCardW - 46, 22)];
            st.numberOfLines = 2;
            st.minimumScaleFactor = 0.7;
            st.text = [NSString stringWithFormat:@"%lu 个语义key → ⚡直写 · 零patch · %@",
                       (unsigned long)f9ks.count, mfStatePersistIsOn() ? @"已持久化" : @"未持久化"];
            st.font = [UIFont systemFontOfSize:10.5];
            st.textColor = [UIColor secondaryLabelColor];
            [bar addSubview:st];
            UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:g_mfCtrl action:@selector(mfShowStatePage)];
            [bar addGestureRecognizer:tap];
            [page addSubview:bar];
            y += 56;
        }
    }
    // v2.58.24: UI 合并(用户反馈) — 旧「🎯判定点按钮」+「🎯判定点卡片条」两个入口
    // 合成一个 F9 同款卡片式交互; 点卡片条直接进列表。规则表(高级)入口移除
    // (判定点主流程 v2.58 起不依赖规则表, 用户从未用过 — 编辑器代码保留, 入口撤)。
    // v2.58.66: 单卡合并(用户: "指令级卡片又是什么鬼") — 全点位一张卡, 副标题分行
    //   显示类型构成; 旧的 🧩 第二张同义卡已删(侦查→入库→一张卡看全)。
    {
        UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 52)];
        bar.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
        bar.layer.cornerRadius = 10;
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(12, 5, g_mfCardW - 46, 22)];
        l.text = @"🎯 判定点(指令级 patch)";
        l.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
        [bar addSubview:l];
        UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(12, 27, g_mfCardW - 46, 22)];
        st.numberOfLines = 3;
        st.minimumScaleFactor = 0.7;
        NSArray *all = mfAppPatchEntDumps();
        // v2.58.77: 按"证据强度"分类报数 — 旧实现一律"共 N 点(N 含截断填充的噪声)",
        //   用户看不出哪些是真解锁候选(mf_debug_79: "12 个"里 8 个是共享 bool 噪声)。
        //   语义锚定 = 调用过 SK API 或有指令级形态锚; 参考 = fan 共现的共享 bool。
        NSUInteger nSem = 0, nRef = 0;
        for (NSDictionary *dd in all) {
            NSString *sh = dd[@"shape"] ?: @"";
            BOOL sem = [sh isEqualToString:@"sk2pro"] || [sh isEqualToString:@"sk2get"]
                    || [sh isEqualToString:@"sk2dat"] || [sh isEqualToString:@"sk2br"]
                    || [sh isEqualToString:@"deepslot"]
                    || [sh isEqualToString:@"ivarRead"] || [sh isEqualToString:@"ivarGetter"]
                    || [sh isEqualToString:@"sk2ver"]
                    || ([sh length] == 0 && [dd[@"score"] intValue] >= 3)
                    || ([sh isEqualToString:@"bool"] && [dd[@"score"] intValue] >= 3);
            if (sem) nSem++; else nRef++;
        }
        NSUInteger nTomb = mfAppPatchTombstoneCount();
        if (all.count) {
            NSMutableString *mt = [NSMutableString stringWithFormat:@"解锁候选 %lu 点(语义锚定)", (unsigned long)nSem];
            if (nRef) [mt appendFormat:@" · 参考 %lu 点(共享getter, 多为噪声)", (unsigned long)nRef];
            if (nTomb) [mt appendFormat:@" · 已删 %lu", (unsigned long)nTomb];
            [mt appendString:@"\n左划[⚡patch][💾持久化][✂删除] · 点卡片看明细"];
            st.text = mt;
        } else if (nTomb) {
            st.text = [NSString stringWithFormat:@"暂无点位(已删 %lu 点, 可恢复) → 点卡片管理", (unsigned long)nTomb];
        } else {
            st.text = @"暂无点位 — 先跑侦查卡";
        }
        st.font = [UIFont systemFontOfSize:10.5];
        st.textColor = [UIColor secondaryLabelColor];
        [bar addSubview:st];
        UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:g_mfCtrl action:@selector(mfAPShowEntDumps)];
        [bar addGestureRecognizer:tap];
        [page addSubview:bar];
        y += 62;
    }
    // v2.58.77: 恢复入口 — 墓碑可清(误删真点的退路)
    {
        NSUInteger nTomb = mfAppPatchTombstoneCount();
        UIButton *btnR = [UIButton buttonWithType:UIButtonTypeSystem];
        btnR.frame = CGRectMake(16, y, g_mfCardW - 32, 36);
        btnR.backgroundColor = nTomb ? [UIColor systemOrangeColor] : [UIColor tertiarySystemFillColor];
        btnR.layer.cornerRadius = 9;
        [btnR setTitle:(nTomb ? [NSString stringWithFormat:@"♻️ 恢复被删点位（清墓碑 %lu 个）", (unsigned long)nTomb]
                              : @"♻️ 无已删点位")
                forState:UIControlStateNormal];
        btnR.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
        [btnR addTarget:g_mfCtrl action:@selector(mfAPRestoreTombstones:) forControlEvents:UIControlEventTouchUpInside];
        [page addSubview:btnR];
        y += 42;
    }
    // v2.58.66: SK2/代码判定点第二张卡已删 — 与 🎯 判定点同义(用户: "又是什么鬼")。
    //   两类点(sk2pro/sk2get)本就入同一持久层, 由上面单卡统一展示与操作。

    // v2.58.77 删: "keychain 票据(链B·开发中)" 占位按钮 + 说明块
    //   用户定案: "别老是搞一些死文案丢在那里" — 未落地的入口不上屏。
    *yio = y + 8;
}
