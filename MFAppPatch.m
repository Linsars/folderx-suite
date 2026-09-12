// MFAppPatch.m — 进程层 patch 引擎 (v2.21.0, 2026-09-04)
// 灵感来源: ReflixPatch-3.0.5 逆向 (vm_protect 写 __text 模式) — 见 reven-recon/REFLIXPATCH-REPORT.md
// 【归属】IAPtools.dylib (IAP 域); 实验模拟页入口; 不碰系统进程
// 【铁律】ctor 有系统进程守卫(IAPtools 既有); 本文件不新增 ctor, 由 MFPanel ctor 按开关拉起
//
// 三层能力:
//   1. 规则引擎: prefs 读 JSON 规则表, bundleID+version 匹配当前进程
//   2. 执行器:   kind=method → objc swizzle;  kind=text → vm_protect(RW)+写字节+icache+恢复RX
//   3. 采集器:   纯被动周期快照 diff (v2.21: 不 hook vm_protect — fishhook 会污染
//                ReflixPatch 的 backtrace 反 hook 检测导致其 abort, 见 2026-09-04 实测)
//
// 规则表格式 (prefs key = mfAppPatchRules, 值 = JSON 字符串):
// [{
//   "bid": "com.magicgroot.gooby", "ver": "3.0.5", "note": "Reflix Pro gate",
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

// ====== 状态 ======
static long g_apHits = 0;          // 成功 patch 数
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

// ====== Mach-O 主程序定位 (MH_EXECUTE, ReflixPatch 同款思路) ======
static uintptr_t apMainImageBase(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE) return (uintptr_t)h;
    }
    return _dyld_image_count() ? (uintptr_t)_dyld_get_image_header(0) : 0;
}

// ====== text patch: vm_protect 三步 (ReflixPatch 同款) ======
// v2.57: 抽出 apTextPatchAt(绝对地址) — 主程序(text 规则)与框架(swifttext 规则)共用执行核
static BOOL apTextPatchAt(uintptr_t target, NSData *expectOld, NSData *newBytes, NSString **err) {
    if (expectOld.length) {
        NSData *cur = [NSData dataWithBytes:(void*)target length:expectOld.length];
        if (![cur isEqualToData:expectOld]) {
            *err = [NSString stringWithFormat:@"old mismatch @%p: cur=%@ want=%@", (void*)target, apBytesToHex(cur.bytes, cur.length), apBytesToHex(expectOld.bytes, expectOld.length)];
            return NO;
        }
    }
    kern_return_t kr = vm_protect(mach_task_self(), target & ~0xFFFUL, 0x1000, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        *err = [NSString stringWithFormat:@"vm_protect RW failed kr=%d", kr];
        return NO;
    }
    memcpy((void*)target, newBytes.bytes, newBytes.length);
    sys_icache_invalidate((void*)target, newBytes.length);
    kr = vm_protect(mach_task_self(), target & ~0xFFFUL, 0x1000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        *err = [NSString stringWithFormat:@"vm_protect RX restore failed kr=%d", kr];
        return NO; // 字节已写, 权限没恢复 — 仍算半成功
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

// ====== v2.56: Keychain 授权豁免(学习自 ScriptingPass 判定链数据源) ======
// 样本(ScriptingPass)授权判定: fetchUserRecordID(CloudKit 身份) + SecItemCopyMatching(Keychain 缓存)
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
        apEntDumpsApply();     // 持久化点位重打(核心)
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
    });
}
static void apEntDumpsSave(void) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:g_entDumps options:0 error:nil];
    if (d) mfWritePrefObj([NSString stringWithFormat:@"mfEntDumps_%@", apCurBundleID()],
                          [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding]);
}
NSArray *mfAppPatchEntDumps(void) { apEntDumpsLoad(); return g_entDumps; }
// F8 扫描点位合并进持久存储(去重: img+sym 相同视为同点)
void mfAppPatchEntDumpsMerge(NSArray *newOnes) {
    if (![newOnes isKindOfClass:[NSArray class]]) return;
    apEntDumpsLoad();
    for (NSDictionary *n in newOnes) {
        if (![n isKindOfClass:[NSDictionary class]]) continue;
        BOOL dup = NO;
        for (NSDictionary *o in g_entDumps)
            if ([o[@"img"] isEqualToString:n[@"img"]] && [o[@"sym"] isEqualToString:n[@"sym"]]) { dup = YES; break; }
        if (!dup) {
            NSMutableDictionary *m = [n mutableCopy];
            m[@"on"] = @NO;                       // 新点位默认未开启(用户左划持久化才开)
            [g_entDumps addObject:m];
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
// 冷启动/热触发: 重打所有 on=YES 点位(持久化执行核心)
void apEntDumpsApply(void) {
    apEntDumpsLoad();
    if (!g_entDumps.count) return;
    for (NSDictionary *d in g_entDumps) {
        if (![d[@"on"] boolValue]) continue;
        NSString *err = nil;
        NSData *newBytes = apHexToBytes(@"20008052c0035fd6");   // mov w0,#1; ret
        if (apSwiftTextPatch(d[@"img"] ?: @"", d[@"sym"] ?: @"", nil, newBytes, &err)) {
            g_apHits++;
            apLog(@"[entdump] ✓ %@ 持久化 patch 重打", [d[@"sym"] lastPathComponent]);
        } else apLog(@"[entdump] ✗ %@: %@", d[@"sym"], err);
    }
}
long mfAppPatchEntDumpCount(void) { apEntDumpsLoad(); return g_entDumps.count; }

// v2.21 教训: 内存首拍在 ctor 才拍, 而 TrollFools 注入的补丁 dylib
// 初始化更早 — patch 在基线之前就打完了, 内存 diff 永远是 0 (假阴性)
// 破法: ReflixiOS 二进制文件 = 原始字节 (主程序 vmaddr偏移==文件偏移),
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
    // v2.22.1: 预置 Reflix 首条规则 (0x7c06f4 tbz→tbnz, 强制走 proAccessOverride 注入路径)
    return @"[\n"
           @"  {\n"
           @"    \"bid\": \"com.magicgroot.gooby\",\n"
           @"    \"ver\": \"3.0.5\",\n"
           @"    \"note\": \"ProGate debug override 强制注入 (tbz→tbnz)\",\n"
           @"    \"patches\": [\n"
           @"      {\"kind\":\"text\",\"off\":\"0x7c06f4\",\"old\":\"94020036\",\"new\":\"94020037\"}\n"
           @"    ]\n"
           @"  }\n"
           @"]";
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
- (void)mfAPEntPatchNow:(NSString *)sym;
- (void)mfAPEntSetOn:(NSString *)sym on:(BOOL)on;
- (void)mfAPKeychainStub;
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
    st.text = on ? @"💾 已持久化 — 冷启动自动重打" : @"未开启 — 左划操作";
    st.textColor = on ? [UIColor systemGreenColor] : [UIColor tertiaryLabelColor];
    return c;
}
// 左划: ⚡立即patch(橙) / 💾持久化开关(绿/灰)
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSDictionary *d = self.items[ip.row];
    NSString *sym = d[@"sym"] ?: @"";
    BOOL on = [d[@"on"] boolValue];
    UIContextualAction *patch = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"⚡patch" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [(id)g_mfCtrl mfAPEntPatchNow:sym];
            done(YES);
        }];
    patch.backgroundColor = [UIColor systemOrangeColor];
    UIContextualAction *persist = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:on ? @"💾取消" : @"💾持久" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [(id)g_mfCtrl mfAPEntSetOn:sym on:!on];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [tv reloadData];
            });
            done(YES);
        }];
    persist.backgroundColor = on ? [UIColor systemGrayColor] : [UIColor systemGreenColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[patch, persist]];
}
@end

// category 续: 判定点操作方法(列表类之后重新开)
@implementation MFPanelCtrl (AppPatchEnt)
static MFAPEntList *g_apEntList = nil;
- (void)mfAPShowEntDumps {
    UIView *page = mfMakePage(@"🎯 判定点", YES);
    g_apEntList = [[MFAPEntList alloc] init];
    g_apEntList.items = mfAppPatchEntDumps();
    UITableView *tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 46, g_mfCardW, g_mfCardH - 46)
                                                    style:UITableViewStylePlain];
    tv.dataSource = g_apEntList;
    tv.delegate = g_apEntList;
    tv.rowHeight = 64;
    tv.separatorStyle = UITableViewCellSeparatorStyleNone;
    [page addSubview:tv];
    mfPushPage(page);
}
- (void)mfAPEntPatchNow:(NSString *)sym {
    // 立即单点 patch: 从 entDumps 找该 sym 打 mov w0,#1; ret
    for (NSDictionary *d in mfAppPatchEntDumps()) {
        if (![d[@"sym"] isEqualToString:sym]) continue;
        NSString *err = nil;
        NSData *newBytes = apHexToBytes(@"20008052c0035fd6");
        if (apSwiftTextPatch(d[@"img"] ?: @"", d[@"sym"] ?: @"", nil, newBytes, &err)) {
            g_apHits++;
            apLog(@"[entdump] ⚡ %@ 立即 patch OK", sym);
            mfToast(@"⚡ 已 patch");
        } else mfToast(err ?: @"patch 失败");
        return;
    }
    mfToast(@"点位不存在(重扫一次)");
}
- (void)mfAPEntSetOn:(NSString *)sym on:(BOOL)on {
    mfAppPatchEntDumpSetOn(sym, on);
    mfToast(on ? @"💾 已持久化 — 冷启动自动重打" : @"已取消持久化");
}
// v2.58 占位: 自签票据写 app keychain(链B) — 实现为占位, 参数已逆向齐待落地
- (void)mfAPKeychainStub {
    mfToast(@"🔐 链B票据写入开发中 — 参数已逆向(LZFSE+HMAC/psc.dv.s1)");
    apLog(@"[entdump] keychain 票据入口被点击(占位) — 自签 Envelope: LZFSE 压缩 + HMAC-SHA256(DeviceSecret, psc.dv.s1) → kcp.ent.snapshot.v1");
}
@end

// ====== 实验模拟页嵌入块 (由 MFPanel.m 的 mfShowLabPage 调用) ======
void mfAppPatchSectionInLabPage(UIView *page, CGFloat *yio) {
    CGFloat y = *yio;
    UILabel *grp = [[UILabel alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 20)];
    grp.text = @"AppPatch 判定点引擎";
    grp.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    grp.textColor = [UIColor secondaryLabelColor];
    [page addSubview:grp];
    y += 24;
    // v2.58 重构(用户六点清单): 引擎开关退役 — 有持久化点位(mfEntDumps)冷启动自动重打;
    //   采集器迁观察模块(MFCompatPatcher 同路); 规则表保留为 text/method 手工高级用法。
    {
        UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 52)];
        bar.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
        bar.layer.cornerRadius = 10;
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(12, 5, g_mfCardW - 46, 22)];
        l.text = @"🎯 判定点卡片";
        l.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
        [bar addSubview:l];
        UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(12, 27, g_mfCardW - 46, 22)];
        st.numberOfLines = 2;
        st.minimumScaleFactor = 0.7;
        st.text = [NSString stringWithFormat:@"侦查→卡片→左划[⚡patch][💾持久化] · 已存 %ld 点(%ld 持久)",
                   mfAppPatchEntDumpCount(), (long)[[mfAppPatchEntDumps() filteredArrayUsingPredicate:
                        [NSPredicate predicateWithFormat:@"on == YES"]] count]];
        st.font = [UIFont systemFontOfSize:10.5];
        st.textColor = [UIColor secondaryLabelColor];
        [bar addSubview:st];
        [page addSubview:bar];
        y += 56;
    }
    UIButton *btnDumps = [UIButton buttonWithType:UIButtonTypeSystem];
    btnDumps.frame = CGRectMake(16, y, (g_mfCardW - 40) / 2, 38);
    [btnDumps setTitle:@"🎯 判定点" forState:UIControlStateNormal];
    [btnDumps addTarget:g_mfCtrl action:@selector(mfAPShowEntDumps) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:btnDumps];
    UIButton *btnRules = [UIButton buttonWithType:UIButtonTypeSystem];
    btnRules.frame = CGRectMake(16 + (g_mfCardW - 40) / 2 + 8, y, (g_mfCardW - 40) / 2, 38);
    [btnRules setTitle:@"📜 规则表(高级)" forState:UIControlStateNormal];
    [btnRules addTarget:g_mfCtrl action:@selector(mfAPShowRulesEditor) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:btnRules];
    y += 44;
    // v2.58 占位: 自签票据写入 app keychain(样本链B手法 — 无插件也亮)
    //   参数已逆向齐: kcp.ent.snapshot.v1 / DeviceSecret kcp.v3.nx7.p0.7f1a / LZFSE+HMAC-SHA256(psc.dv.s1)
    UIButton *btnKC = [UIButton buttonWithType:UIButtonTypeSystem];
    btnKC.frame = CGRectMake(16, y, g_mfCardW - 32, 38);
    btnKC.backgroundColor = [UIColor systemTealColor];
    btnKC.layer.cornerRadius = 9;
    [btnKC setTitle:@"🔐 keychain 票据持久化(链B · 开发中)" forState:UIControlStateNormal];
    [btnKC setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btnKC.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [btnKC addTarget:g_mfCtrl action:@selector(mfAPKeychainStub) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:btnKC];
    y += 44;
    UILabel *note = [[UILabel alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 64)];
    note.text = @"冷启动: 有持久化点位自动重打(mov w0,#1; ret), 无开关依赖。\n规则表 = text/method 手工高级用法, 判定点主流程不依赖。\n日志已并入 mf_debug.log。";
    note.numberOfLines = 0;
    note.font = [UIFont systemFontOfSize:11];
    note.textColor = [UIColor secondaryLabelColor];
    [page addSubview:note];
    y += 68;
    *yio = y;
}
