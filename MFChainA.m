// MFChainA.m — 链A 模块(v2.59.4 直写版)
// 架构定位(2026-09-11 定案): SK2 双链设计
//   A 链(通用层): F8 点位数=0 且 SK 形态=SK2 → 启用 — 典型 SK2 app(gongju 型, 单二进制,
//     App Store strip 主二进制符号) 无点位可打; 但权益状态必落 @objc 可见层(PremiumStore 类
//     _TtC 单例 + 实例字段), 我们注入在目标进程内, 运行时枚举可达。
//   B 链(精确层): F8 点位数≥1 → 启用(已有 swifttext 恒真 patch)
// v2.59.2-3 = 探测: 类枚举 + 权益类识别 + ivar/method dump + 侦查自动触发。
// v2.59.4 = 直写:
//   ★ 实例定位(methods=0 的纯 Swift 类没有 getter/KVC 入口 — 常规死路):
//     L1 = app __DATA/__DATA_CONST 段 qword 扫描 + isa 匹配(Swift static let 全局指针就在这);
//     L2 = 已定位的候选类实例, 按其 ivar extent 扫字节找目标类 isa(容器类持有 store 的形态)。
//   ★ 直写 = ivar_getOffset + 1 字节裸写(写前 8 字节安全读做指针预检 — 疑似包装字段不盲写)
//     + 回读验证 + 字节级日志(下版展开 @Published box 的判据来源)。
//   ★ 持久化 mfChainAWrites_<bid> + 冷启动 3s 重打(Sk2 回填时机实测调)。
// Swift ivar 事实(2.59.3 验收): Bool 存储属性 encoding 非 "B" → 候选判定三态放宽(B/空/?) + 名字启发式。

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <string.h>

// ====== MF 复用接口(extern) ======
extern CGFloat g_mfCardW, g_mfCardH;
extern UIView *mfMakePage(NSString *title, BOOL showBack);
extern void mfPushPage(UIView *page);
extern void mfPopPage(void);
extern void mfToast(NSString *s);
extern void mfLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
@class MFPanelCtrl;
@interface MFPanelCtrl : NSObject
- (void)mfChainAShowPage;
@end

#pragma mark - 权益类识别: 名称启发式
static NSArray *chainACandidatePats(void) {
    static NSArray *pats; static dispatch_once_t o;
    dispatch_once(&o, ^{
        pats = @[@"Premium", @"Paywall", @"ProAccess", @"Entitle", @"AABill", @"Subscription",
                 @"Purchase", @"License"];
    });
    return pats;
}
static BOOL chainAClassIsCandidate(const char *cname) {
    if (!cname) return NO;
    NSString *cn = [NSString stringWithUTF8String:cname];
    if (cn.length < 4) return NO;
    if ([cn hasPrefix:@"SK"] || [cn hasPrefix:@"NS"] || [cn hasPrefix:@"UI"]) return NO;
    NSArray *patsL = chainACandidatePats();
    for (NSString *p in patsL)
        if ([cn rangeOfString:p options:NSCaseInsensitiveSearch].length) return YES;
    return NO;
}

#pragma mark - bool 候选判定(v2.59.4: encoding 三态放宽 + 字段名启发式)
static BOOL chainAIsBoolIvar(const char *ty) {
    if (!ty || !ty[0] || !strcmp(ty, "?")) return YES;   // Swift 存储属性常态: 无 encoding
    return !strcmp(ty, "B");
}
static NSArray *chainABoolNamePats(void) {
    static NSArray *p; static dispatch_once_t o;
    dispatch_once(&o, ^{ p = @[@"purchas", @"paid", @"unlock", @"pro", @"premium", @"entitle", @"member", @"subscri"]; });
    return p;
}
static BOOL chainABoolNameHit(NSString *ivName) {
    NSString *low = ivName.lowercaseString;
    NSArray *bPatsL = chainABoolNamePats();
    for (NSString *p in bPatsL)
        if ([low rangeOfString:p].length) return YES;
    return NO;
}
// MFRecon 侦查行复用(跨文件 — 非 static 导出)
BOOL chainABoolNameHitExt(NSString *ivName) { return chainABoolNameHit(ivName); }

#pragma mark - 安全读(vm_read_overwrite probe — 候选 qword 解引用可能落未映射页)
// SDK 14.5 的 mach_vm.h 带 #error, 用 MFProcCapture 同款 vm_read_overwrite(vm_address_t 32 位截断无虞 — iOS 用户态地址 < 32G)
static BOOL chainASafeReadQ(uint64_t addr, uint64_t *out) {
    vm_size_t sz = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)addr, 8,
                          (vm_address_t)out, &sz) != KERN_SUCCESS || sz != 8) return NO;
    return YES;
}
// 候选 qword 是否长得像堆指针(高位非全 0/全 F, 落在 iOS 用户堆范围, 8 对齐)
static BOOL chainALooksHeapPtr(uint64_t q) {
    if (q < 0x100000000ULL || q > 0x800000000ULL) return NO;   // iOS 用户态堆 ~0x1_0000_0000..0x8_0000_0000(32G 封顶)
    if (q & 0xFF00000000000000ULL) return NO;
    return YES;
}
#define CHAINA_ISA_MASK 0x7FFFFFFFFFF8ULL

#pragma mark - 实例定位(链A 直写的前提 — methods=0 类没有常规入口)
// L1: app 镜像可写数据段 qword 扫描, isa 匹配目标类 — Swift "static let store = Store()"
//     的全局强指针就在 __DATA; static let 是 Swift 单例主流写法。
static NSArray *chainAScanDataSegFor(Class target, const char *imgPath) {
    if (!target || !imgPath) return nil;
    uint32_t n = _dyld_image_count();
    const struct mach_header_64 *hdr = NULL;
    intptr_t slide = 0;
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && !strcmp(nm, imgPath)) {
            hdr = (const struct mach_header_64 *)_dyld_get_image_header(i);
            // ★ v2.59.8 崩溃修复: _dyld_get_image_slide() 收 mach_header* 而非索引
            //   (dyld4 签名 — 传索引=把整数当指针解引用, 读 0x1 直接 SIGSEGV,
            //    160804.ips 等连崩 7 次实锤)。索引版是 _dyld_get_image_vmaddr_slide(i)。
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!hdr) return nil;
    uintptr_t targetMasked = (uintptr_t)target & CHAINA_ISA_MASK;
    NSMutableArray *found = [NSMutableArray new];
    const struct load_command *lc = (const char *)hdr + sizeof(*hdr);
    for (uint32_t ci = 0; ci < hdr->ncmds; ci++, lc = (const char *)lc + lc->cmdsize) {
        if (lc->cmd != LC_SEGMENT_64) continue;
        const struct segment_command_64 *seg = (const void *)lc;
        if (strcmp(seg->segname, "__DATA") && strcmp(seg->segname, "__DATA_CONST")
            && strcmp(seg->segname, "__DATA_DIRTY") && strcmp(seg->segname, "__DATA_CONST_DIRTY")) continue;
        uintptr_t start = (uintptr_t)slide + seg->vmaddr, end = start + seg->vmsize;
        for (uintptr_t p = start; p + 8 <= end; p += 8) {
            uint64_t q = 0;
            // v2.59.8: 数据段直读改安全读 — 崩溃日志显示段内也有读失败页(prot 位不含 READ 的页)
            if (!chainASafeReadQ((uint64_t)p, &q)) continue;
            if (!chainALooksHeapPtr(q)) continue;
            uint64_t isaQ = 0;
            if (!chainASafeReadQ(q, &isaQ)) continue;
            if ((isaQ & CHAINA_ISA_MASK) != targetMasked) continue;
            id inst = (__bridge id)(void *)q;
            if (object_getClass(inst) == target) {       // runtime 二次确认(含子类否决/isa 位处理)
                BOOL dup = NO;
                for (id e in found) if (e == inst) { dup = YES; break; }
                if (!dup) {
                    [found addObject:inst];
                    if (found.count >= 8) return found;  // 异常多 = 垃圾误配保护, 截断
                }
            }
        }
    }
    return found;
}

// L3: 全堆扫描(v2.59.9 新增 — L1 的存储位置假设修正)。
//   ★ 2.59.8 验收实锤: gongju 全 4 类 L1/L2 双 miss。SwiftUI app 的 ObservableObject
//     (@StateObject/.environmentObject) 强指针在 AttributeGraph 堆结构/UIHostingController
//     持有链里, __DATA 全局段根本没有(static let 单例形态的假设对 SwiftUI app 不成立)。
//   做法: vm_region_recurse 64 遍历 RW 匿名堆区(malloc zone), qword 解引用 isa 匹配。
//   性能: 堆区几十 MB, vm_read_overwrite 逐 qword 太慢 — 按 region 整块读后内存匹配。
static NSArray *chainAScanHeapFor(NSArray *targets) {
    if (!targets.count) return nil;
    NSMutableArray *found = [NSMutableArray new];
    mach_port_t task = mach_task_self();
    vm_address_t addr = 0;
    vm_size_t size = 0;
    natural_t depth = 0;
    while (1) {
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (vm_region_recurse_64(task, &addr, &size, &depth,
                                 (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS) break;
        if (info.is_submap) { depth++; continue; }   // ★ 进入子映射: depth+1 后重入同 addr(API 语义), 不加 addr
        {
            BOOL rw = (info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE);
            BOOL anon = info.share_mode == SM_PRIVATE;
            BOOL heapRange = addr >= 0x100000000ULL && (addr + size) <= 0x800000000ULL;
            BOOL shareModeOK = (info.share_mode == SM_EMPTY || info.share_mode == SM_PRIVATE || info.share_mode == SM_COW);
            if (rw && anon && heapRange && shareModeOK && size >= 0x1000 && size <= 0x4000000) {
                // 整块读进本地缓冲再匹配(vm_read 大块单次调用, 避免逐 qword trap 开销)
                uint64_t nQ = size / 8;
                uint64_t *buf = malloc(size);
                vm_size_t got = 0;
                if (buf && vm_read_overwrite(task, addr, size, (vm_address_t)buf, &got) == KERN_SUCCESS && got >= 16) {
                    for (uint64_t qi = 0; qi + 1 < nQ && found.count < 24; qi++) {
                        uint64_t q = buf[qi];
                        if (!chainALooksHeapPtr(q) || (q & 0xF)) continue;   // 16 对齐过滤 — ObjC 对象全 16 对齐, 砍掉 15/16 解引用量
                        // 快路径: q 指向的对象头就在本 region 内 → 直接 buf 读(零 trap)
                        uint64_t iv = 0;
                        uint64_t off = q - (uint64_t)addr;
                        if (off + 8 <= got) iv = *(uint64_t *)((uint8_t *)buf + off);
                        else if (!chainASafeReadQ(q, &iv)) continue;   // 区外对象才走 trap
                        for (Class t in targets) {
                            if (((uintptr_t)t & CHAINA_ISA_MASK) != (iv & CHAINA_ISA_MASK)) continue;
                            id inst = (__bridge id)(void *)q;
                            if (object_getClass(inst) == t) {
                                BOOL dup = NO;
                                for (id e in found) if (e == inst) { dup = YES; break; }
                                if (!dup) [found addObject:inst];
                            }
                        }
                    }
                }
                if (buf) free(buf);
            }
        }
        addr += size;
        if (addr == 0) break;
        if (found.count >= 24) break;
    }
    return found;
}

// L2: 供体实例内存(ivar extent 内)找目标类 isa — 容器类/ViewModel 持有 store 的形态。
//     extent = 供体类最大 ivar offset + 16(末字段读余量), 无 ivar 时跳过。
static void chainAScanDonorFor(Class target, id donor, NSMutableArray *out) {
    Class dc = object_getClass(donor);
    unsigned ivc = 0;
    Ivar *ivs = class_copyIvarList(dc, &ivc);
    if (!ivc || !ivs) { if (ivs) free(ivs); return; }
    uintptr_t extent = 16;
    for (unsigned k = 0; k < ivc; k++) {
        uintptr_t o = (uintptr_t)ivar_getOffset(ivs[k]);
        if (o + 16 > extent) extent = o + 16;
    }
    uintptr_t targetMasked = (uintptr_t)target & CHAINA_ISA_MASK;
    uint8_t *base = (uint8_t *)(__bridge void *)donor;
    for (uintptr_t p = 16; p + 8 <= extent; p += 8) {    // 前 16 字节是 isa+refcnt, 跳过
        uint64_t q = *(uint64_t *)(base + p);            // 供体实例内偏移, 已知有效对象范围, 直接读
        if (!chainALooksHeapPtr(q)) continue;
        uint64_t isaQ = 0;
        if (!chainASafeReadQ(q, &isaQ)) continue;
        if ((isaQ & CHAINA_ISA_MASK) != targetMasked) continue;
        id inst = (__bridge id)(void *)q;
        if (object_getClass(inst) == target) {
            BOOL dup = NO;
            for (id e in out) if (e == inst) { dup = YES; break; }
            if (!dup && out.count < 8) [out addObject:inst];
        }
    }
    free(ivs);
}

// 实例定位总入口: L1(目标类所在镜像全局段) + L1(所有候选类镜像全局段) + L2(供体实例内扫)
// fwd: g_chainARows 快照(定义在下方枚举区) — 此处在定义之前使用, 提前声明。
static NSArray *chainARowsSnapshotInternal(void);
static NSArray *chainAFindInstances(NSString *clsName) {
    Class target = objc_getClass(clsName.UTF8String);
    if (!target) return nil;
    NSMutableArray *out = [NSMutableArray new];
    // v2.59.9: L3 全堆扫描(SwiftUI @StateObject 形态 — 2.59.8 验收 L1/L2 全 miss 实锤)
    // ARC 铁律: for-in 内联非 Copy 命名返回函数会判非桥接指针 — 局部变量接住
    NSArray *heapHits = chainAScanHeapFor(@[target]);
    for (id inst in heapHits) {
        BOOL dup = NO; for (id e in out) if (e == inst) { dup = YES; break; }
        if (!dup && out.count < 8) [out addObject:inst];
    }
    if (out.count) return out;
    // L1a: 目标类镜像(备选路径 — static let 单例形态)
    NSArray *rowsV1 = chainARowsSnapshotInternal();
    for (NSDictionary *row in rowsV1) {
        NSString *imgP = row[@"imgPath"];
        if (![imgP isKindOfClass:[NSString class]] || imgP.length == 0) continue;
        NSArray *hitsV1 = chainAScanDataSegFor(target, imgP.UTF8String);
        for (id inst in hitsV1)
            if (object_getClass(inst) == target) {
                BOOL dup = NO; for (id e in out) if (e == inst) { dup = YES; break; }
                if (!dup) [out addObject:inst];
            }
    }
    // L2: 供体 = 任何候选类实例, 扫其内存找目标 isa
    if (out.count < 8) {
        NSMutableArray *donors = [NSMutableArray new];
        NSArray *rowsV2 = chainARowsSnapshotInternal();
        for (NSDictionary *row in rowsV2) {
            Class dc = objc_getClass([row[@"name"] UTF8String]);
            if (!dc) continue;
            NSArray *hitsV2 = chainAScanDataSegFor(dc, [row[@"imgPath"] UTF8String]);
            for (id inst in hitsV2) {
                BOOL dup = NO; for (id e in donors) if (e == inst) { dup = YES; break; }
                if (!dup) [donors addObject:inst];
            }
        }
        for (id donor in donors) chainAScanDonorFor(target, donor, out);
    }
    return out;
}

#pragma mark - 直写核心(ivar 偏移 1 字节裸写 + 字节级日志)
// 决策树:
//   1) ivar 不存在 → 报错(computed property, 无存储 — B 链/fixup 域)
//   2) KVC 先试(@objc 存在 setter 时干净; 纯 Swift 类会抛异常, 接住继续)
//   3) 裸写: offset 处 8 字节安全读 — 指针形态(疑似 @Published box/对象字段)→ 不盲写, 报
//      "疑似包装字段"给日志(下版展开 box 的判据); 否则写 1 字节 0x01 + 回读验证。
// 返回 nil=成功; 非 nil=描述。outDesc 恒有值(进日志/toast 的字节级明细)。
static NSString *chainAWriteField(NSString *clsName, NSString *ivName, id target,
                                  NSString **outDesc) {
    Class c = objc_getClass(clsName.UTF8String);
    if (!c) { if (outDesc) *outDesc = @"类未找到"; return @"类未找到(已卸载?)"; }
    if (!target) { if (outDesc) *outDesc = @"实例 nil"; return @"实例为 nil"; }
    Ivar iv = class_getInstanceVariable(c, ivName.UTF8String);
    if (!iv) { if (outDesc) *outDesc = @"ivar 不存在"; return @"ivar 不存在(computed? 待 B 链/fixup)"; }
    ptrdiff_t off = ivar_getOffset(iv);
    uint8_t *p = (uint8_t *)(__bridge void *)target + off;
    // 写前 8 字节快照(判定字段形态 + 日志)
    uint64_t before = 0;
    BOOL gotQ = chainASafeReadQ((uint64_t)(uintptr_t)p, &before);
    uint8_t b0 = p[0];
    if (gotQ && chainALooksHeapPtr(before)) {
        NSString *msg = [NSString stringWithFormat:@"offset %td 写前 qword=%llx 疑似指针/包装字段 — 不盲写(下版展开 box)", off, before];
        if (outDesc) *outDesc = msg;
        return @"疑似包装字段(@Published box?) — 不盲写";
    }
    // KVC 机会主义(纯 Swift 无 accessor 会抛 NSUndefinedKey, 接住走裸写)
    NSString *kvcKey = [ivName copy];
    BOOL kvcOK = NO;
    @try { [target setValue:@YES forKey:kvcKey]; kvcOK = (p[0] != 0); } @catch (NSException *e) { kvcOK = NO; }
    if (!kvcOK) p[0] = 0x01;
    uint8_t after = p[0];
    NSString *desc = [NSString stringWithFormat:@"%@.%@ off=%td before=%02x after=%02x%@",
        clsName, ivName, off, b0, after, kvcOK ? @" (KVC)" : @" (裸写)"];
    if (outDesc) *outDesc = desc;
    if (after != 0x01) return @"写后回读不为 1 — 失败";
    return nil;
}

#pragma mark - 持久化(mfChainAWrites_<bid>: [{cls,fld,on}] 冷启动重打)
// ★ ARC 规则: 函数名含 Copy/New/Retain/Create 才享受隐式命名桥接, "Key" 返回 OC 指针被判
//   非桥接指针 — 改 cast 链写法, 不依赖命名约定。
static NSString *chainAWritesKey(void) {
    NSString *bid = [NSBundle mainBundle].bundleIdentifier;
    return [NSString stringWithFormat:@"mfChainAWrites_%@", (NSString *)(bid ?: @"unknown")];
}
// ★ 同类 ARC 坑: 名字不带 Copy/New/Retain/Create 的 OC 返回函数在 writeToFile: 参数位
//   也被判非桥接指针 — 干脆改成返回值 + 局部变量写法, 全函数只此一处。
static NSString *MFPrefsPathC(void) {
    return @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist";
}
static NSMutableArray *chainAWritesLoad(void) {
    NSString *pp = MFPrefsPathC();
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:pp];
    id raw = d[chainAWritesKey()];
    if ([raw isKindOfClass:[NSString class]]) {
        NSArray *a = [NSJSONSerialization JSONObjectWithData:[raw dataUsingEncoding:NSUTF8StringEncoding]
                                                    options:NSJSONReadingMutableContainers error:nil];
        if ([a isKindOfClass:[NSArray class]]) return [a mutableCopy];
    }
    return [NSMutableArray new];
}
static void chainAWritesSave(NSMutableArray *arr) {
    NSData *jd = [NSJSONSerialization dataWithJSONObject:arr options:0 error:nil];
    if (!jd) return;
    NSString *pp = MFPrefsPathC();
    NSMutableDictionary *d = [[NSDictionary dictionaryWithContentsOfFile:pp] mutableCopy] ?: [NSMutableDictionary new];
    d[chainAWritesKey()] = [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding];
    [d writeToFile:pp atomically:YES];
}
static void chainAWritesAdd(NSString *cls, NSString *fld) {
    if (cls.length == 0 || fld.length == 0) return;
    NSMutableArray *arr = chainAWritesLoad();
    for (NSDictionary *r in arr)
        if ([r[@"cls"] isEqualToString:cls] && [r[@"fld"] isEqualToString:fld]) return;
    [arr addObject:@{@"cls": cls, @"fld": fld, @"on": @YES}];
    chainAWritesSave(arr);
    mfLog(@"[chainA] 💾 规则入库: %@.%@", cls, fld);
}
static void chainAWritesRemove(NSString *cls, NSString *fld) {
    NSMutableArray *arr = chainAWritesLoad();
    NSMutableArray *keep = [NSMutableArray new];
    for (NSDictionary *r in arr)
        if (!([r[@"cls"] isEqualToString:cls] && [r[@"fld"] isEqualToString:fld])) [keep addObject:r];
    chainAWritesSave(keep);
}

#pragma mark - 枚举(安全模式: 原子快照 + strdup 自持; 只扫 .app 自有镜像)
// 事故链教训(勿重蹈): 逐索引 _dyld_get_image_name 动态 dlopen 悬挂指针(Crash#2);
//   objc_copyClassList 全进程 realize 触发 Swift 泛型 conformance 空指针(Crash#1)。
static NSMutableArray *g_chainARows = nil;   // [{name, img, imgPath, ivars, methods, bools}]
static NSObject *g_chainALock = nil;
static BOOL g_chainAScanned = NO;

static NSDictionary *chainADumpClass(const char *cname, NSString *imgLeaf, const char *imgPath) {
    Class c = objc_getClass(cname);
    if (!c) return nil;
    unsigned ivc = 0;
    Ivar *ivs = class_copyIvarList(c, &ivc);
    NSMutableArray *ivars = [NSMutableArray array];
    for (unsigned k = 0; k < ivc; k++) {
        const char *in = ivar_getName(ivs[k]);
        const char *ty = ivar_getTypeEncoding(ivs[k]);
        if (!in) continue;
        BOOL b = chainAIsBoolIvar(ty);
        [ivars addObject:[NSString stringWithFormat:@"%@%s%@",
            b ? @"bool " : @"", in, b ? @"" : [NSString stringWithFormat:@" (%s)", ty ?: "?"]]];
    }
    if (ivs) free(ivs);
    NSMutableArray *methods = [NSMutableArray array];
    for (int meta = 0; meta < 2; meta++) {
        Class cc = meta ? object_getClass(c) : c;
        unsigned mc = 0;
        Method *ms = class_copyMethodList(cc, &mc);
        for (unsigned k = 0; k < mc; k++) {
            const char *sel = sel_getName(method_getName(ms[k]));
            if (!sel) continue;
            [methods addObject:[NSString stringWithFormat:@"%c%s", meta ? '+' : '-', sel]];
        }
        if (ms) free(ms);
    }
    unsigned boolCnt = 0;
    for (NSString *iv in ivars) {
        if (![iv hasPrefix:@"bool "]) continue;
        NSString *nm = [iv substringFromIndex:5];
        NSRange sp = [nm rangeOfString:@" ("];
        if (sp.length) nm = [nm substringToIndex:sp.location];
        if (chainABoolNameHit(nm)) boolCnt++;
    }
    return @{
        @"name": [NSString stringWithUTF8String:cname],
        @"img": imgLeaf,
        @"imgPath": imgPath ? [NSString stringWithUTF8String:imgPath] : @"",
        @"ivars": ivars,
        @"methods": methods,
        @"bools": @(boolCnt),
    };
}

static void chainAScan(void) {
    if (!g_chainALock) g_chainALock = [NSObject new];
    @synchronized (g_chainALock) {
        if (g_chainAScanned) return;
        g_chainAScanned = YES;
        g_chainARows = [NSMutableArray array];

        unsigned ic = 0;
        const char **imgs = objc_copyImageNames(&ic);
        if (!imgs || !ic) return;
        char **safe = malloc(sizeof(char *) * ic);
        unsigned nSafe = 0;
        for (unsigned i = 0; i < ic; i++) {
            const char *im = imgs[i];
            if (!im || !strstr(im, ".app/")) continue;
            safe[nSafe] = strdup(im);
            nSafe++;
        }
        free(imgs);

        unsigned clsFound = 0;
        for (unsigned i = 0; i < nSafe; i++) {
            const char *img = safe[i];
            unsigned cn = 0;
            char **names = objc_copyClassNamesForImage(img, &cn);
            if (!names) continue;
            NSString *leaf = [[NSString stringWithUTF8String:img] lastPathComponent];
            for (unsigned j = 0; j < cn; j++) {
                if (!chainAClassIsCandidate(names[j])) continue;
                NSDictionary *d = chainADumpClass(names[j], leaf, img);
                if (d) { [g_chainARows addObject:d]; clsFound++; }
            }
            free(names);
        }
        for (unsigned i = 0; i < nSafe; i++) free(safe[i]);
        free(safe);
        mfLog(@"[chainA] 探测: %u 个权益类(bool 字段候选见详情)", clsFound);
        for (NSDictionary *d in g_chainARows) {
            // v2.59.8: bool 名单只列名字命中的(encoding 三态放宽后 String/Decimal 也带"bool "前缀,
            //   日志行不做过滤会把 _billTitle/_totalAmount 全印出来 — 判定噪声)
            NSMutableArray *bools = [NSMutableArray array];
            for (NSString *iv in (NSArray *)d[@"ivars"])
                if ([iv hasPrefix:@"bool "]) {
                    NSString *nm = [iv substringFromIndex:5];
                    NSRange sp = [nm rangeOfString:@" ("];
                    if (sp.length) nm = [nm substringToIndex:sp.location];
                    if (chainABoolNameHit(nm)) [bools addObject:nm];
                }
            mfLog(@"[chainA]   %@ · ivars %lu · methods %lu%@",
                d[@"name"], (unsigned long)[(NSArray *)d[@"ivars"] count],
                (unsigned long)[(NSArray *)d[@"methods"] count],
                bools.count ? [NSString stringWithFormat:@" · bool: %@", [bools componentsJoinedByString:@"/"]] : @"");
        }
    }
}

// 对外只读接口
unsigned long mfChainAClassCount(void) {
    @synchronized (g_chainALock ?: (g_chainALock = [NSObject new])) {
        return g_chainARows.count;
    }
}
void mfChainAProbe(void);
NSArray *mfChainARowsSnapshot(void) {
    @synchronized (g_chainALock ?: (g_chainALock = [NSObject new])) {
        return g_chainARows ?: @[];
    }
}
// 内部快照(chainAFindInstances 定义在枚举区之前 — fwd 桥)
static NSArray *chainARowsSnapshotInternal(void) {
    return mfChainARowsSnapshot();
}
void mfChainAProbe(void) {
    chainAScan();
}

#pragma mark - 冷启动重打(MFPanel ctor → 延迟 3s; SK2 回填时机实测调)
void mfChainABootReplay(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSMutableArray *arr = chainAWritesLoad();
        if (!arr.count) return;
        // 探测未跑时先补跑(冷启动直接重打场景)
        chainAScan();
        unsigned ok = 0, fail = 0;
        for (NSMutableDictionary *r in arr) {
            if (![r[@"on"] boolValue]) continue;
            NSString *cls = r[@"cls"], *fld = r[@"fld"];
            NSArray *insts = chainAFindInstances(cls);
            if (!insts.count) { fail++; mfLog(@"[chainA] ✗ 重打 %@.%@ — 实例未定位(L1/L2 均 0)", cls, fld); continue; }
            for (id inst in insts) {
                NSString *desc = nil;
                NSString *err = chainAWriteField(cls, fld, inst, &desc);
                if (err) { fail++; mfLog(@"[chainA] ✗ 重打 %@ — %@", desc ?: err, err); }
                else { ok++; mfLog(@"[chainA] ✓ 重打 %@ (inst %p)", desc, inst); }
            }
        }
        mfLog(@"[chainA] Boot 重打完成: ok=%u fail=%u (3s)", ok, fail);
    });
}

#pragma mark - A 链列表页
@interface MFChainAList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) NSArray *rows;
@end
@implementation MFChainAList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return self.rows.count; }
- (CGFloat)tableView:(UITableView *)tv heightForRowAtIndexPath:(NSIndexPath *)ip { return 64; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *idt = @"mfChainARow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:idt];
    if (!c) {
        c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:idt];
        c.backgroundColor = UIColor.clearColor;
        c.selectionStyle = UITableViewCellSelectionStyleNone;
        UILabel *nm = [UILabel new]; nm.tag = 301;
        nm.font = [UIFont fontWithName:@"Menlo" size:11.5]; nm.textColor = [UIColor labelColor];
        nm.lineBreakMode = NSLineBreakByTruncatingMiddle;
        UILabel *img = [UILabel new]; img.tag = 302;
        img.font = [UIFont fontWithName:@"Menlo" size:9.5]; img.textColor = [UIColor secondaryLabelColor];
        img.lineBreakMode = NSLineBreakByTruncatingMiddle;
        UILabel *st = [UILabel new]; st.tag = 303;
        st.font = [UIFont systemFontOfSize:10]; st.textColor = [UIColor tertiaryLabelColor];
        [c.contentView addSubview:nm]; [c.contentView addSubview:img]; [c.contentView addSubview:st];
    }
    NSDictionary *d = self.rows[ip.row];
    CGFloat w = g_mfCardW - 32;
    UILabel *nm = [c.contentView viewWithTag:301], *img = [c.contentView viewWithTag:302], *st = [c.contentView viewWithTag:303];
    nm.frame = CGRectMake(16, 5, w - 16, 17);
    img.frame = CGRectMake(16, 22, w - 16, 15);
    st.frame = CGRectMake(16, 39, w - 16, 15);
    nm.text = d[@"name"];
    img.text = [NSString stringWithFormat:@"%@ · ivars %lu · methods %lu",
        d[@"img"], (unsigned long)[(NSArray *)d[@"ivars"] count], (unsigned long)[(NSArray *)d[@"methods"] count]];
    unsigned bools = [d[@"bools"] unsignedIntValue];
    st.text = bools ? [NSString stringWithFormat:@"bool 候选 %u 个 — 点行直写", bools] : @"无 bool ivar(纯 Swift 判定, 待 B 链/fixup)";
    st.textColor = bools ? [UIColor systemGreenColor] : [UIColor tertiaryLabelColor];
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    NSDictionary *d = self.rows[ip.row];
    NSString *clsName = d[@"name"];
    UIView *page = mfMakePage([NSString stringWithFormat:@"⚡ %@", clsName], YES);

    // 实例定位(L1 全局段 + L2 供体扫描 — methods=0 类的唯一入口)
    NSArray *insts = chainAFindInstances(clsName);
    UILabel *tgt = [[UILabel alloc] initWithFrame:CGRectMake(16, 48, g_mfCardW - 32, 16)];
    tgt.font = [UIFont fontWithName:@"Menlo" size:10];
    tgt.textColor = insts.count ? [UIColor systemGreenColor] : [UIColor systemOrangeColor];
    if (insts.count) {
        NSMutableString *s = [NSMutableString stringWithFormat:@"实例 %lu 个:", (unsigned long)insts.count];
        for (id i in insts) [s appendFormat:@" %p", i];
        tgt.text = s;
    } else {
        tgt.text = @"实例 0 个(L1 全局段+L2 供体均 miss) — ⚡ 仍可点(写时报错进日志)";
    }
    [page addSubview:tgt];

    __block CGFloat y = 74;
    for (NSString *ivRaw in (NSArray *)d[@"ivars"]) {
        BOOL isBool = [ivRaw hasPrefix:@"bool "];
        NSString *ivName = isBool ? [ivRaw substringFromIndex:5] : ivRaw;
        NSString *bare = [ivName componentsSeparatedByString:@" ("][0];
        if (isBool && chainABoolNameHit(bare)) {
            // ⚡置YES — Swift 存储属性直写候选
            UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
            btn.frame = CGRectMake(16, y, g_mfCardW - 32, 34);
            [btn setTitle:[NSString stringWithFormat:@"⚡ %@ = YES", ivName] forState:UIControlStateNormal];
            btn.titleLabel.font = [UIFont fontWithName:@"Menlo" size:11];
            btn.backgroundColor = [UIColor systemBlueColor];
            btn.tintColor = UIColor.whiteColor;
            btn.layer.cornerRadius = 8;
            objc_setAssociatedObject(btn, "chainACls", clsName, OBJC_ASSOCIATION_RETAIN);
            objc_setAssociatedObject(btn, "chainAFld", bare, OBJC_ASSOCIATION_RETAIN);
            [btn addTarget:self action:@selector(chainAZap:) forControlEvents:UIControlEventTouchUpInside];
            [page addSubview:btn];
            y += 42;
        } else {
            UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 16)];
            l.font = [UIFont fontWithName:@"Menlo" size:10];
            l.textColor = [UIColor secondaryLabelColor];
            l.text = ivName;
            [page addSubview:l];
            y += 22;
        }
    }
    UITextView *tv2 = [[UITextView alloc] initWithFrame:CGRectMake(12, y + 6, g_mfCardW - 24, MAX(60, g_mfCardH - y - 70))];
    tv2.font = [UIFont fontWithName:@"Menlo" size:10];
    tv2.editable = NO; tv2.selectable = YES;
    tv2.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    tv2.layer.cornerRadius = 10;
    NSMutableString *txt = [NSMutableString stringWithString:@"== methods(@objc) ==\n"];
    for (NSString *m in (NSArray *)d[@"methods"]) [txt appendFormat:@"  %@\n", m];
    [tv2 setText:txt];
    [page addSubview:tv2];
    mfPushPage(page);
}
- (void)chainAZap:(UIButton *)b {
    NSString *cls = objc_getAssociatedObject(b, "chainACls");
    NSString *fld = objc_getAssociatedObject(b, "chainAFld");
    if (!cls || !fld) { mfToast(@"按钮上下文丢失"); return; }
    NSArray *insts = chainAFindInstances(cls);
    if (!insts.count) {
        mfToast(@"实例未定位 — L1/L2 均 0(下版加 alloc 捕获)");
        mfLog(@"[chainA] ⚡ %@.%@ ✗ 实例未定位(L1/L2 miss)", cls, fld);
        return;
    }
    unsigned ok = 0;
    for (id inst in insts) {
        NSString *desc = nil;
        NSString *err = chainAWriteField(cls, fld, inst, &desc);
        if (err) mfLog(@"[chainA] ⚡ ✗ %@ — %@", desc ?: @"", err);
        else { ok++; mfLog(@"[chainA] ⚡ ✓ %@", desc); }
    }
    if (ok) {
        mfToast([NSString stringWithFormat:@"✓ %@ = YES × %lu 实例 — 已入库自动重打", fld, (unsigned long)ok]);
        chainAWritesAdd(cls, fld);
    } else {
        mfToast(@"✗ 写失败 — 见 mf_debug.log 字节明细");
    }
}
@end
static MFChainAList *g_chainAList = nil;

@implementation MFPanelCtrl (ChainA)
- (void)mfChainAShowPage {
    chainAScan();
    if (!g_chainARows.count) {
        mfToast(@"无权益类候选(类名无 Premium/Paywall/Entitle 语义)");
        mfLog(@"[chainA] 探测: 0 命中 — 非典型型, 考虑 fixup 重绑(开发中)");
        return;
    }
    UIView *page = mfMakePage(@"🅰️ A链 · 权益类直写", YES);
    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 32, 34)];
    hint.text = @"点行进详情 → ⚡置YES 直写(自动入库, 冷启动 3s 重打); 实例定位: __DATA 扫描+供体扫描";
    hint.numberOfLines = 2;
    hint.font = [UIFont systemFontOfSize:10.5];
    hint.textColor = [UIColor secondaryLabelColor];
    [page addSubview:hint];
    g_chainAList = [[MFChainAList alloc] init];
    g_chainAList.rows = g_chainARows;
    UITableView *tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 84, g_mfCardW, g_mfCardH - 84)
                                                    style:UITableViewStylePlain];
    tv.dataSource = g_chainAList;
    tv.delegate = g_chainAList;
    tv.rowHeight = 64;
    tv.separatorStyle = UITableViewCellSeparatorStyleNone;
    [page addSubview:tv];
    mfPushPage(page);
}
@end
