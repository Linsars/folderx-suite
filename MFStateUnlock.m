// MFStateUnlock.m — v2.58.20 状态型判定引擎(F9)
// yimuliaoran 定谳(2026-09-13): VIP 判定不在代码里, 在 UserDefaults:
//   boolForKey("membership.hasLifetime") + objectForKey("membership.monthlyExpiration")
//   as? Date 比较 → vipStatus enum → 全显示层
// F8v1/v2/v3 对此类 app 全部空转(判定无函数实体, fan-in/形态分类/patch 均无从着力)。
// 本引擎取代 F8 优先级: 侦查先定数据源形态, 状态型 → 直写解锁; 代码型 → F8 兜底。
//
// 侦查: __cstring 静态扫语义 key(词表+camelCase点分风格) ∩ 运行时 dictionaryRepresentation
// 解锁: setBool:YES / setObject:distantFuture(expir 类) + synchronize — 零 patch
// 持久: mfStateWrites_<bid> 记录已写 key, 冷启动 Boot 重打(app 启动清写时复写)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <string.h>
#import "MFPanel.h"

// ==================================================================
// v2.58.133 (dbg_124 定谳): F9 存储层扩到「标准 + App Group 双存储」。
//   根因: target-app 权益 key 不在标准 UserDefaults(f9inj 写 11 个落盘但不亮),
//   而在 App Group(widget_pro_unlocked 实测在 group.app.target)。F9 旧实现
//   只扫/写标准 → 点位恒 0(用户: "点位都没有")。
//   修法: 解析主程序 __TEXT,__entitlements 拿 application-groups, 侦查并入 group,
//   直写双写(标准 + 各 group) — 哪个是真实存储即命中; 都不在 = 内存派生(走网络层)。
// ==================================================================
// 读主程序 entitlements → com.apple.security.application-groups(缓存)
// v2.58.134 fix(dbg_125 崩溃定谳): 133 用 _NSGetExecutablePath(buf, sizeof buf) —
//   第二参数是 uint32_t* 指针, 传值 1024 被解引用 → KERN_INVALID_ADDRESS at 0x400 → SEGV。
//   且返回值逻辑反了(0=成功)。→ 照抄 stateStaticKeys 模式: NSBundle executablePath +
//   NSData mapped 读 + 原始字节偏移, 零新 API 零手动 mmap。
static NSArray *mfAppGroupNames(void) {
    static NSArray *cached = nil; static dispatch_once_t o;
    dispatch_once(&o, ^{
        NSMutableArray *names = [NSMutableArray array];
        // ① entitlements 解析(主程序 __TEXT,__entitlements) — TrollStore 应用有效
        NSString *exe = [[NSBundle mainBundle] executablePath];
        if (exe) {
            NSData *d = [NSData dataWithContentsOfFile:exe options:NSDataReadingMappedIfSafe error:NULL];
            if (d.length >= 0x1000) {
                const uint8_t *p = d.bytes;
                uint32_t ncmds = *(const uint32_t *)(p + 16);
                const uint8_t *lc = p + 32;
                const char *ent = NULL; size_t entLen = 0;
                for (uint32_t c = 0; c < ncmds; c++) {
                    const struct load_command *cmd = (const struct load_command *)lc;
                    if (cmd->cmdsize < 8) break;
                    if (cmd->cmd == 0x19 /*LC_SEGMENT_64*/) {
                        const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
                        if (!strcmp(sg->segname, "__TEXT")) {
                            const struct section_64 *sec = (const struct section_64 *)(lc + sizeof(struct segment_command_64));
                            for (uint32_t j = 0; j < sg->nsects; j++) {
                                if (!strcmp(sec->sectname, "__entitlements"))
                                    { ent = (const char *)p + sec->offset; entLen = sec->size; }
                                sec++;
                            }
                        }
                    }
                    lc += cmd->cmdsize;
                }
                if (ent && entLen) {
                    NSDictionary *e = [NSPropertyListSerialization propertyListWithData:
                                       [NSData dataWithBytes:ent length:entLen]
                                       options:0 format:NULL error:NULL];
                    NSArray *g = e[@"com.apple.security.application-groups"];
                    if ([g isKindOfClass:[NSArray class]])
                        for (id x in g) if ([x isKindOfClass:[NSString class]]) [names addObject:x];
                }
            }
        }
        // ② 兜底: bundleID 推导。App Store 应用 entitlements 不在 __TEXT,__entitlements
        //    (在签名区)→ ①解析会空。group.<bundleID> 是 Apple 标准命名, f9inj 已证
        //    group.app.target 有效(写入读回=1)。非法 group 读回空 → 被 stores 过滤。
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        if (bid.length) {
            [names addObject:[@"group." stringByAppendingString:bid]];
            NSArray *parts = [bid componentsSeparatedByString:@"."];
            if (parts.count >= 2) {
                NSMutableString *rev = [NSMutableString string];
                for (NSUInteger i = parts.count; i-- > 0;) { if (rev.length) [rev appendString:@"."]; [rev appendString:parts[i]]; }
                [names addObject:[@"group." stringByAppendingString:rev]];
            }
        }
        // 去重
        cached = [NSSet setWithArray:names].allObjects;
        mfLog(@"[f9] App Groups 候选: %lu 个 (%@) — entitlements+bundleID推导",
              (unsigned long)cached.count, cached.count ? cached : @"无");
    });
    return cached;
}
// 所有 App Group 的 NSUserDefaults 实例(缓存; 只收非空 = 真实 group)
static NSArray *mfStateGroupStores(void) {
    static NSArray *stores = nil; static dispatch_once_t o;
    dispatch_once(&o, ^{
        NSMutableArray *m = [NSMutableArray array];
        NSMutableArray *live = [NSMutableArray array];
        for (NSString *g in mfAppGroupNames()) {
            NSUserDefaults *u = [[NSUserDefaults alloc] initWithSuiteName:g];
            if (!u) continue;
            NSDictionary *dd = [u dictionaryRepresentation];
            if (dd.count) { [m addObject:u]; [live addObject:g]; }   // 非空=app 有此 entitlement 且写过
        }
        stores = m;
        mfLog(@"[f9] 实存 App Group(非空): %lu 个 (%@)",
              (unsigned long)live.count, live.count ? live : @"无");
    });
    return stores;
}
// 合并「标准 + 各 group」的实存值 → {key: value}(标准优先)。侦查/直写都基于它。
static NSDictionary *mfStateAllLiveValues(void) {
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    for (NSUserDefaults *g in mfStateGroupStores()) {
        NSDictionary *gd = [g dictionaryRepresentation];
        for (NSString *k in gd.allKeys) m[k] = gd[k];
    }
    NSDictionary *std = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
    for (NSString *k in std.allKeys) m[k] = std[k];   // 标准优先
    return m;
}

// 跨文件接口(MFRecon 调侦查 / ctor 调重打)
NSArray *mfStateProbeKeys(void);
void mfStateBootReplay(void);
BOOL mfStatePersistIsOn(void);
void mfStateSetPersist(NSArray *keys, BOOL on);

// 文件级前向声明(读侧守卫在文件头引用, 定义在下方)
static NSString *statePrefsPath(void);
static NSDictionary *stateStore(void);
static void stateStoreSet(NSDictionary *d);   // v2.58.119: recon 缓存落盘用
static NSString *stateWritesKey(void);
static BOOL stateKeyIsDate(NSString *k);

// v2.58.49: 读侧守卫 — SK2(JWS) 型 app 启动时用事务流重算覆写 UserDefaults,
//   写侧直写被打回原形(实测: 12 点位⚡+F9 直写全中, 仍不亮)。
//   终局解法: 读侧拦截 — 对持久化守卫 key 恒返解锁值, app 写什么无所谓。
static IMP g_orig_ud_objectForKey = NULL;
static IMP g_orig_ud_boolForKey = NULL;
static BOOL g_stateGuardOn = NO;

static NSArray *stateGuardedKeys(void) {
    id ks = stateStore()[stateWritesKey()];
    return [ks isKindOfClass:[NSArray class]] ? ks : @[];
}
static BOOL stateGuardKeyReverse(NSString *k) {
    static NSArray *inv = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        inv = @[@"missing", @"missed", @"lost", @"revok", @"block",
                @"cancel", @"disabl", @"suspend", @"banned", @"expired"];
    });
    NSString *lk = k.lowercaseString;
    for (NSString *w in inv) if ([lk containsString:w]) return YES;
    return NO;
}
static id new_ud_objectForKey(id self, SEL _cmd, NSString *key) {
    if (g_stateGuardOn && [key isKindOfClass:[NSString class]]) {
        for (NSString *k in stateGuardedKeys()) {
            if (![k isEqualToString:key]) continue;
            if (stateGuardKeyReverse(k)) return nil;                  // 反向词: 不存在=解锁
            // v2.58.138 类型守卫: 只对实存 Bool/Date 恒返解锁值。
            //   dict/array/Data 恒返原值 — 强返 YES 毁类型(current_entitlements 该是集合)。
            id live = ((id(*)(id, SEL, id))g_orig_ud_objectForKey)(self, _cmd, key);
            if ([live isKindOfClass:[NSDictionary class]] || [live isKindOfClass:[NSArray class]] || [live isKindOfClass:[NSData class]]) return live;
            return stateKeyIsDate(k) ? [NSDate distantFuture] : @YES; // Bool/Date 恒解锁值
        }
    }
    return ((id(*)(id, SEL, id))g_orig_ud_objectForKey)(self, _cmd, key);
}
static BOOL new_ud_boolForKey(id self, SEL _cmd, NSString *key) {
    if (g_stateGuardOn && [key isKindOfClass:[NSString class]]) {
        for (NSString *k in stateGuardedKeys()) {
            if (![k isEqualToString:key]) continue;
            if (stateGuardKeyReverse(k)) return NO;
            return YES;
        }
    }
    return ((BOOL(*)(id, SEL, id))g_orig_ud_boolForKey)(self, _cmd, key);
}
// v2.58.138: 字典快照读路径 — app 走 dictionaryRepresentation 读(字典下标)时,
//   objectForKey:/boolForKey: 钩子拦不到。钩住它, 守卫 key 恒返解锁值。
//   只 patch 实存 Bool 的 key(不在字典不塞, dict/array 值不碰 — 131/128 教训)。
static IMP g_orig_ud_dictRep = NULL;
static id new_ud_dictRep(id self, SEL _cmd) {
    id orig = ((id(*)(id, SEL))g_orig_ud_dictRep)(self, _cmd);
    if (!g_stateGuardOn || ![orig isKindOfClass:[NSDictionary class]]) return orig;
    NSMutableDictionary *m = [orig mutableCopy];
    BOOL patched = NO;
    for (NSString *k in stateGuardedKeys()) {
        id v = m[k];
        if (!v) continue;                                              // 不在字典不塞
        if (![v isKindOfClass:[NSNumber class]]) continue;             // dict/array/Data/Date 不碰
        if (strcmp(object_getClassName(v), "__NSCFBoolean") != 0) continue;
        if (stateGuardKeyReverse(k)) { [m removeObjectForKey:k]; patched = YES; continue; }
        m[k] = @YES; patched = YES;
    }
    return patched ? m : orig;
}
void mfStateGuardInstall(void) {
    if (g_stateGuardOn) return;
    if (!stateGuardedKeys().count) return;   // 无持久化守卫列表, 不装
    Class c = NSClassFromString(@"NSUserDefaults");
    if (!c) return;
    Method m1 = class_getInstanceMethod(c, @selector(objectForKey:));
    Method m2 = class_getInstanceMethod(c, @selector(boolForKey:));
    Method m3 = class_getInstanceMethod(c, @selector(dictionaryRepresentation));
    if (!m1 || !m2) return;
    if (!g_orig_ud_objectForKey) {
        g_orig_ud_objectForKey = method_getImplementation(m1);
        method_setImplementation(m1, (IMP)new_ud_objectForKey);
    }
    if (!g_orig_ud_boolForKey) {
        g_orig_ud_boolForKey = method_getImplementation(m2);
        method_setImplementation(m2, (IMP)new_ud_boolForKey);
    }
    if (m3 && !g_orig_ud_dictRep) {
        g_orig_ud_dictRep = method_getImplementation(m3);
        method_setImplementation(m3, (IMP)new_ud_dictRep);
    }
    g_stateGuardOn = YES;
    mfLog(@"[f9] 读侧守卫已装: %lu key(objectForKey+boolForKey+dictRep) — app 覆写无碍, 读取恒解锁值", (unsigned long)stateGuardedKeys().count);
}
// v2.58.140: 卸守卫 — IMP 已 swizzle 无法安全还原, 用 flag 关闭(守卫逻辑首行判 g_stateGuardOn,
//   关掉后三个钩子全部透传原实现)。配合「全部恢复并删除」用。
void mfStateGuardUninstall(void) {
    if (!g_stateGuardOn) return;
    g_stateGuardOn = NO;
    mfLog(@"[f9] 读侧守卫已卸(flag off, 钩子透传原实现)");
}

// MFPanelCtrl 定义在 MFPanel.m — 最小前向声明让 category 可编译(MFAppPatch.m 同款)
@interface MFPanelCtrl : NSObject @end
// 声明段在前(UI 块的 [(id)g_mfCtrl mfStateZap:] 需要它), 实现段在本文件尾部
BOOL mfStateKeyIsDataBacked(NSString *key);   // v2.58.64: 编码数据型 key 判定(定义在本文件 F9 段)

@interface MFPanelCtrl (StateUnlock)
- (void)mfShowStatePage;
- (void)mfStateZap:(NSString *)key;
- (void)mfStateZapOff:(NSString *)key;
- (void)mfStateDeleteKey:(NSString *)key;
- (void)mfStateZapAll;
- (void)mfStateRestoreDeleteAll:(UIButton *)sender;   // v2.58.140: 全部恢复并删除(取代冗余持久化按钮)
@end


// —— 词表: plist 权益 key 语义(yimuliaoran 命名族实锤: membership.hasLifetime/monthlyExpiration) ——
static NSArray *kStateKeyWords = nil;
static NSArray *kStateDateWords = nil;   // 命中 → Date 型(distantFuture), 其余 Bool 型

static void stateWordsInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        kStateKeyWords = @[@"vip", @"member", @"premium", @"purchas", @"entitle",
                          @"lifetime", @"expir", @"unlock", @"subscri",
                          @"isvip", @"ispro", @"is_paid", @"ispaid", @"pro_"];  // v2.58.21: 词表补缺
        kStateDateWords = @[@"expir", @"date", @"until"];
    });
}

// —— key 形态门(v2.58.21): ServeLog 事故定谳 — 词表扫 __cstring 会命中英文文案/URL
// ("No active ... purchase ..."/"https://apps.apple.com/..."). 真 plist key 是紧凑标识符:
// a.b 点分 camelCase, 无空格, 无 ://, 段内仅字母数字+._-. 句子/URL 一律不是 key ——
// 命中即清名单(词表误命中 = 误判状态型 = 掐死代码型 app 的 F8 路线, ServeLog 实锤)。
static BOOL stateKeyShapeOK(NSString *k) {
    if ([k containsString:@" "]) return NO;                      // 句子/短语(文案)
    if ([k containsString:@"://"]) return NO;                    // URL
    if ([k containsString:@"/"]) return NO;                      // 路径(含 URL 遗漏形态)
    NSArray *segs = [k componentsSeparatedByString:@"."];
    if (segs.count < 2 && ![k containsString:@"_"]) return NO;   // v2.58.136: 纯单词(无点无下划线)不是 key; snake_case(premium_unlocked) 放行
    static NSCharacterSet *okChars = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ okChars = [[NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._"] invertedSet]; });
    for (NSString *s in segs) {
        if (!s.length) return NO;                                // a..b / .x 畸形
        if ([s rangeOfCharacterFromSet:okChars].location != NSNotFound) return NO; // 段内仅 [A-Za-z0-9_-]
    }
    return YES;
}

static BOOL stateKeyMatch(NSString *k) {
    if (k.length < 4 || k.length > 64) return NO;
    if (![k containsString:@"."] && ![k containsString:@"_"]) return NO;   // v2.58.136: 点分 OR snake_case(target-app 权益 key 全是 premium_unlocked 无点形态, 强制含点全杀)
    if ([k hasPrefix:@"com."]) return NO;       // 排除第三方 SDK 域名风格 key(RC 映射等 — 缓存 dict, 直写会破坏)
    if (!stateKeyShapeOK(k)) return NO;         // v2.58.21: 形态门 — 文案/URL/路径不是 key
    // v2.58.35: 静态污染排除(76 条假案定谳) — __cstring 里的 i18n 文案段
    //   (discover./drawer./paywall./testflight./player./settings./badge_/detail.)
    //   与 Firebase 埋点段 (measurement./error_/.token/.mocking_) 词表全误命中
    //   ("pro_header"/"lifetime"/"expiresIn" 子串), 但全是文案 key 非状态位。
    static NSArray *i18nSegs = nil;
    static dispatch_once_t o2;
    dispatch_once(&o2, ^{ i18nSegs = @[@"discover.", @"drawer.", @"paywall.", @"testflight.",
                                        @"settings.", @"player.", @"badge_", @"measurement.",
                                        @"adservices_", @"log2_", @"caching_", @"error_",
                                        @"sk2_invalid", @"manage_subscription", @"general_tier"]; });
    for (NSString *seg in i18nSegs)
        if ([k hasPrefix:seg] || [k containsString:[@"." stringByAppendingString:seg]]) return NO;
    NSString *lk = [k lowercaseString];
    for (NSString *w in kStateKeyWords)
        if ([lk containsString:w]) return YES;
    return NO;
}
static BOOL stateKeyIsDate(NSString *k) {
    NSString *lk = [k lowercaseString];
    for (NSString *w in kStateDateWords)
        if ([lk containsString:w]) return YES;
    return NO;
}

// 静态: 主二进制 __cstring 扫 key 候选(磁盘 mmap, __TEXT fileoff=0 直读)
static NSMutableSet *stateStaticKeys(void) {
    NSMutableSet *out = [NSMutableSet set];
    @autoreleasepool {
        NSString *exe = [[NSBundle mainBundle] executablePath];
        if (!exe) return out;
        NSData *d = [NSData dataWithContentsOfFile:exe options:NSDataReadingMappedIfSafe error:NULL];
        if (d.length < 0x1000) return out;
        const uint8_t *p = d.bytes;
        // mach_header_64 + LC 段表找 __TEXT.__cstring
        uint32_t ncmds = *(const uint32_t *)(p + 16);
        const uint8_t *lc = p + 32;
        for (uint32_t c = 0; c < ncmds; c++) {
            const struct load_command *cmd = (const struct load_command *)lc;
            if (cmd->cmd == 0x19 /*LC_SEGMENT_64*/) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
                if (!strcmp(sg->segname, "__TEXT") && sg->fileoff == 0) {
                    const struct section_64 *sc = (const struct section_64 *)(lc + sizeof(struct segment_command_64));
                    for (uint32_t s = 0; s < sg->nsects; s++, sc++) {
                        if (!strcmp(sc->sectname, "__cstring") && sc->size && sc->offset) {
                            const char *cp = (const char *)(p + sc->offset);
                            uint64_t coff = 0;
                            while (coff + 4 < sc->size) {
                                const char *s2 = cp + coff;
                                size_t sl = strnlen(s2, (size_t)(sc->size - coff));
                                if (sl >= 4 && sl <= 64) {
                                    NSString *k = [NSString stringWithUTF8String:s2];
                                    if (stateKeyMatch(k)) [out addObject:k];
                                }
                                coff += sl + 1;
                            }
                        }
                    }
                }
            }
            lc += cmd->cmdsize;
        }
    }
    return out;
}

// —— 侦查: 静态候选 ∩ 运行时实存 key, 再并运行时语义命中(实存+词表=app 自己写过的) ——
// 返回: [{key, live, isDate}] — live=NO 的静态 key 是"判定读但从未写"(未购买态)
NSArray *mfStateProbeKeys(void) {
    stateWordsInit();
    @autoreleasepool {
        NSMutableSet *cand = stateStaticKeys();
        // v2.58.133: 运行时实存 key 兜底 — 标准 + App Group 合并(语义过滤后并入)
        NSDictionary *live = mfStateAllLiveValues();
        for (NSString *k in live.allKeys)
            if (stateKeyMatch(k)) [cand addObject:k];
        // 诊断: 分存储计数(判读权益在标准还是 group)
        NSDictionary *stdOnly = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        NSUInteger nGrp = 0; for (NSString *k in live.allKeys) if (!stdOnly[k]) nGrp++;
        mfLog(@"[f9] 实存 key: 合计 %lu · 仅 group %lu · 标准 %lu",
              (unsigned long)live.count, (unsigned long)nGrp, (unsigned long)stdOnly.count);
        NSMutableArray *out = [NSMutableArray array];
        for (NSString *k in [cand allObjects]) {
            id v = live[k];
            // v2.58.137: 只列实存 Bool 的 key — 57 个里 20+ 误报(member_expression 是
            //   Swift 关键字 / SSH_.._Message 是 UI 文案 / add_member_to_group 是操作名),
            //   非实存 Bool 的不进卡片(写了也跳过, 列出来是噪音)。
            if (![v isKindOfClass:[NSNumber class]]) continue;
            if (strcmp(object_getClassName(v), "__NSCFBoolean") != 0) continue;   // Int/Data/dict 不进
            [out addObject:@{
                @"key": k,
                @"live": @(live[k] != nil),
                @"isDate": @(stateKeyIsDate(k)),
                @"liveVal": live[k] ?: @"",
            }];
        }
        [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            // Bool 型优先(核心解锁位), 实存优先, 字母序
            BOOL da = [a[@"isDate"] boolValue], db_ = [b[@"isDate"] boolValue];
            if (da != db_) return da ? NSOrderedDescending : NSOrderedAscending;
            BOOL la = [a[@"live"] boolValue], lb = [b[@"live"] boolValue];
            if (la != lb) return la ? NSOrderedAscending : NSOrderedDescending;
            return [a[@"key"] compare:b[@"key"]];
        }];
        return out;
    }
}

// —— 解锁: 单 key 直写(Bool→YES / Date→distantFuture / 反向词→删 / 容器→跳过) ——
long mfStateUnlockApplyKey(NSString *key, BOOL on) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    // v2.58.133: 双写 标准 + 各 App Group(哪个是真实存储即命中)
    NSArray *stores = [@[ud] arrayByAddingObjectsFromArray:mfStateGroupStores()];
    if (!on) {
        for (NSUserDefaults *s in stores) [s removeObjectForKey:key];
        mfLog(@"[f9] ⚡状态直写 %@ = remove → (已删, %lu stores)", key, (unsigned long)stores.count);
        return 1;
    }
    // v2.58.47: 反向语义词表 — missing/lost/revok 类 key **存在本身 = 锁定态**,
    //   写 YES/distantFuture 恰好强化"缺失中"(dbg_50: missingSince 写 YES 不亮)。
    //   正确解锁 = 删 key(缺失记录不存在 = 从未缺失)。
    static NSArray *invWords = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        invWords = @[@"missing", @"missed", @"lost", @"revok", @"block",
                     @"cancel", @"disabl", @"suspend", @"banned", @"expired"];
    });
    NSString *lk = key.lowercaseString;
    for (NSString *w in invWords) {
        if ([lk containsString:w]) {
            for (NSUserDefaults *s in stores) [s removeObjectForKey:key];
            mfLog(@"[f9] ⚡状态直写 %@ = REMOVE(反向语义词 %@ — 存在=锁定, 删=解锁)", key, w);
            return 1;
        }
    }
    // v2.58.47: 容器类型跳过 — records/transactions 类 key 实存 dict/array,
    //   写 Bool 毁类型, app 解析失败等于白写(dbg_50: verifiedRecords 写 YES 不亮)。
    id cur = nil;
    for (NSUserDefaults *s in stores) { id v = [s objectForKey:key]; if (v) { cur = v; break; } }
    if (cur && ([cur isKindOfClass:[NSDictionary class]] || [cur isKindOfClass:[NSArray class]])) {
        mfLog(@"[f9] ⚡状态直写 %@ 跳过 — 实存类型 %@(容器记录集, 伪造无意义)", key, NSStringFromClass([cur class]));
        return 1;
    }
    // v2.58.64: 编码数据 key 跳过 — 记录集不能凭空造, 跳过并标注。
    if (mfStateKeyIsDataBacked(key)) {
        mfLog(@"[f9] ⚡状态直写 %@ 跳过 — 编码数据 key(Data/JSON 记录集), 写 Bool 类型不符", key);
        return 1;
    }
    // v2.58.137 (dbg_128 定谳): 类型守卫 — 只翻实存 Bool(__NSCFBoolean)的 key。
    //   盲写 Bool=YES 毁类型: entitlement_scope 该是 String / current_entitlements 该是
    //   集合(SK 权益快照) / pro_expires_at_ms 该是 Int ms → app 读不了自己的快照 → 必然不亮。
    //   且 57 个里 20+ 误报(UI文案/Swift关键字/操作名)。→ 实存非 Bool 的 key 全跳过不碰。
    {
        id curV = nil;
        for (NSUserDefaults *s in stores) { id v = [s objectForKey:key]; if (v) { curV = v; break; } }
        if (!curV || strcmp(object_getClassName(curV), "__NSCFBoolean") != 0) {
            mfLog(@"[f9] ⚡状态直写 %@ 跳过 — 实存类型 %@(只翻 Bool 状态位, 非 Bool 毁类型)", key, curV ? NSStringFromClass([curV class]) : @"不存在");
            return 0;
        }
    }
    for (NSUserDefaults *s in stores) {
        if (stateKeyIsDate(key))
            [s setObject:[NSDate distantFuture] forKey:key];
        else
            [s setBool:YES forKey:key];
        [s synchronize];
    }
    id after = [ud objectForKey:key];
    mfLog(@"[f9] ⚡状态直写 %@ = %@ → %@ (落盘 %lu stores, 类型:%@)", key, on ? @"YES/distantFuture" : @"remove",
          [after description], (unsigned long)stores.count, after ? NSStringFromClass([after class]) : @"nil");
    return 1;
}

// v2.58.64: 编码数据型 key 判定 — app 侧走 dataForKey:/setObject(Data) 的 key,
//   写 Bool 类型不符 → app 解析失败 → 依赖该记录集的功能不亮(dbg_67"部分解锁"根因)。
//   判据: ①当前值已是 NSData → 铁证 ②名字含 Records/Snapshot/Transactions 等记录集词
//   (实测目标记录集 key 实证; 记录集不能凭空伪造 → 跳过而非瞎写)
BOOL mfStateKeyIsDataBacked(NSString *key) {
    if (!key.length) return NO;
    id cur = [[NSUserDefaults standardUserDefaults] objectForKey:key];
    if ([cur isKindOfClass:[NSData class]]) return YES;
    NSString *lk = key.lowercaseString;
    static NSArray *kW;
    static dispatch_once_t o;
    dispatch_once(&o, ^{ kW = @[@"records", @"snapshot", @"transactions", @"receipt", @"payload"]; });
    for (NSString *w in kW) if ([lk containsString:w]) return YES;
    return NO;
}

// —— 一键全开: 全部 key 直写 ——
long mfStateUnlockApplyAll(NSArray *keys) {
    long n = 0;
    for (NSDictionary *d in keys)
        n += mfStateUnlockApplyKey(d[@"key"], YES);
    return n;
}

// —— UI: F9 状态解锁页(v2.58.20 主路线 — 状态型判定 app 的解锁入口) ——
@interface MFStateList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *items;
@end
@implementation MFStateList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return self.items.count; }
- (CGFloat)tableView:(UITableView *)tv heightForRowAtIndexPath:(NSIndexPath *)ip { return 58; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *idt = @"mfStateRow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:idt];
    if (!c) {
        c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:idt];
        c.backgroundColor = UIColor.clearColor;
        c.selectionStyle = UITableViewCellSelectionStyleNone;
        UILabel *k = [UILabel new]; k.tag = 301;
        k.font = [UIFont fontWithName:@"Menlo" size:11]; k.textColor = [UIColor labelColor];
        k.lineBreakMode = NSLineBreakByTruncatingMiddle;
        UILabel *v = [UILabel new]; v.tag = 302;
        v.font = [UIFont systemFontOfSize:10]; v.textColor = [UIColor tertiaryLabelColor];
        v.lineBreakMode = NSLineBreakByTruncatingMiddle;
        [c.contentView addSubview:k]; [c.contentView addSubview:v];
    }
    NSDictionary *d = self.items[ip.row];
    UILabel *k = [c.contentView viewWithTag:301], *v = [c.contentView viewWithTag:302];
    CGFloat w = g_mfCardW - 32;
    k.frame = CGRectMake(16, 6, w, 18);
    v.frame = CGRectMake(16, 26, w, 16);
    k.text = [NSString stringWithFormat:@"%@%@", d[@"key"], [d[@"isDate"] boolValue] ? @"  📅Date" : @""];
    v.text = [d[@"live"] boolValue] ?
        [NSString stringWithFormat:@"实存: %@ — 点⚡改写", d[@"liveVal"]] :
        @"静态判定key(未购买态) — ⚡直写解锁";
    v.textColor = [d[@"live"] boolValue] ? [UIColor systemOrangeColor] : [UIColor systemTealColor];
    return c;
}
// 左划: ⚡直写(橙) / ✂删除(红) — v2.58.61 用户要求: F9 点位也要能删
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSString *key = self.items[ip.row][@"key"];
    UIContextualAction *zap = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"⚡直写" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [(id)g_mfCtrl mfStateZap:key];
            done(YES);
        }];
    zap.backgroundColor = [UIColor systemOrangeColor];
    UIContextualAction *del = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleDestructive
        title:@"✂删除" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            // 从侦查缓存删 key — 下次侦查不再出现; 已持久化的同步清出重打清单
            [(id)g_mfCtrl mfStateDeleteKey:key];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                NSMutableArray *items = [self.items mutableCopy];
                for (NSInteger i = (NSInteger)items.count - 1; i >= 0; i--)
                    if ([items[i][@"key"] isEqualToString:key]) [items removeObjectAtIndex:(NSUInteger)i];
                self.items = items;
                [tv reloadData];
            });
            done(YES);
        }];
    del.backgroundColor = [UIColor systemRedColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[zap, del]];
}
@end
static MFStateList *g_stateList = nil;

// v2.58.35: 侦查=唯一采集器(用户架构定案) — recon 采集的 stateKeys 缓存于此, F9
//   全部消费点只读缓存; 缓存空(未跑过侦查)时回退原 mfStateProbeKeys()(保 UI 不空,
//   但定性只认侦查卡)。缓存带 ts, 冷启动过期(数据是侦查时快照)。
static NSArray *g_reconStateKeys = nil;
static BOOL g_reconRan = NO;      // v2.58.67: 侦查跑过(即使结果为空) — 防空缓存反复触发全量扫
static NSString *stateReconCacheKey(void) {
    return [NSString stringWithFormat:@"reconKeys_%@", stateWritesKey()];
}
void mfStateReconCacheSet(NSArray *keys) {
    g_reconStateKeys = [keys copy];
    g_reconRan = YES;             // 侦查已跑(空结果也算) — 不再重复触发
    // v2.58.119: 落盘 — 修复"重开 app 后 F9 卡片被隐藏"(用户实测)。
    //   旧实现纯内存, 冷启动 g_reconStateKeys=nil → mfStateKeysForUI()=@[] → 卡片消失。
    //   只存 key 名(liveVal 可能是非 plist 类型), 读回时按当前 UserDefaults 重建结构。
    NSMutableArray *names = [NSMutableArray array];
    for (NSDictionary *d in keys)
        if ([d isKindOfClass:[NSDictionary class]] && [d[@"key"] isKindOfClass:[NSString class]])
            [names addObject:d[@"key"]];
    NSMutableDictionary *sd = [stateStore() mutableCopy] ?: [NSMutableDictionary dictionary];
    sd[stateReconCacheKey()] = names;
    stateStoreSet(sd);
}
// v2.58.61: F9 ✂删除 — 从侦查缓存移除单 key
void mfStateReconCacheRemoveKey(NSString *key) {
    if (!g_reconStateKeys.count) return;
    NSMutableArray *arr = [g_reconStateKeys mutableCopy];
    for (NSInteger i = (NSInteger)arr.count - 1; i >= 0; i--)
        if ([arr[i][@"key"] isEqualToString:key]) [arr removeObjectAtIndex:(NSUInteger)i];
    g_reconStateKeys = [arr copy];
    // v2.58.119: 同步落盘 — 否则重启后 ✂ 掉的 key 复活
    NSMutableArray *names = [NSMutableArray array];
    for (NSDictionary *d in g_reconStateKeys)
        if ([d[@"key"] isKindOfClass:[NSString class]]) [names addObject:d[@"key"]];
    NSMutableDictionary *sd = [stateStore() mutableCopy] ?: [NSMutableDictionary dictionary];
    sd[stateReconCacheKey()] = names;
    stateStoreSet(sd);
}
NSArray *mfStateKeysForUI(void) {
    if (g_reconStateKeys.count) return g_reconStateKeys;
    // v2.58.119: 内存空(冷启动) → 从盘恢复 — 修复"重开 app 后 F9 卡片被隐藏"
    id saved = stateStore()[stateReconCacheKey()];
    if ([saved isKindOfClass:[NSArray class]] && [saved count]) {
        NSDictionary *live = mfStateAllLiveValues();   // v2.58.133: 标准+group
        NSMutableArray *out = [NSMutableArray array];
        for (NSString *k in saved) {
            if (![k isKindOfClass:[NSString class]]) continue;
            [out addObject:@{ @"key": k, @"live": @(live[k] != nil),
                              @"isDate": @(stateKeyIsDate(k)), @"liveVal": live[k] ?: @"" }];
        }
        g_reconStateKeys = [out copy];
        return g_reconStateKeys;
    }
    // v2.58.119: 兜底 — 用户已💾持久化的 key 也认(即使侦查缓存被清/从未落盘)
    id writes = stateStore()[stateWritesKey()];
    if ([writes isKindOfClass:[NSArray class]] && [writes count]) {
        NSDictionary *live = mfStateAllLiveValues();   // v2.58.133: 标准+group
        NSMutableArray *out = [NSMutableArray array];
        for (NSString *k in writes) {
            if (![k isKindOfClass:[NSString class]]) continue;
            [out addObject:@{ @"key": k, @"live": @(live[k] != nil),
                              @"isDate": @(stateKeyIsDate(k)), @"liveVal": live[k] ?: @"" }];
        }
        g_reconStateKeys = [out copy];
        return g_reconStateKeys;
    }
    return @[];   // v2.58.54: 缓存空 = 未跑侦查 — 页面触发统一采集器, 不再独立扫(用户定案回归)
}

void mfShowStatePage(void) {
    UIView *page = mfMakePage(@"🔓 状态解锁 F9", YES);
    // v2.58.54: 缓存空 = 未跑侦查 → 现场触发统一采集器(mfReconFingerprint), 不再独立扫
    extern NSDictionary *mfReconFingerprint(void);   // MFRecon.m 统一采集器
    UILabel *hintWait = nil;
    if (!g_reconStateKeys.count && !g_reconRan) {
        hintWait = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 32, 30)];
        hintWait.font = [UIFont systemFontOfSize:11];
        hintWait.textColor = [UIColor secondaryLabelColor];
        hintWait.text = @"侦查缓存为空 — 正在跑统一采集器(侦查=唯一采集器)…";
        hintWait.tag = 991;
        [page addSubview:hintWait];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            mfReconFingerprint();   // 统一采集器: 填 g_reconStateKeys + F8/F10 点位全链
            dispatch_async(dispatch_get_main_queue(), ^{
                [hintWait removeFromSuperview];
                mfShowStatePage();   // 重建页面(递归一次, 缓存已热)
            });
        });
    }
    NSArray *keys = mfStateKeysForUI();
    mfLog(@"[f9] 侦查: %lu 个语义 key%@ (源: %@)", (unsigned long)keys.count, keys.count ? @"" : @"(无 — 该 app 非状态型判定)",
        g_reconStateKeys.count ? @"侦查卡缓存" : (g_reconRan ? @"已跑侦查(结果空)" : @"未跑侦查(等待统一采集器)"));
    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 32, 30)];
    hint.font = [UIFont systemFontOfSize:11];
    hint.textColor = [UIColor secondaryLabelColor];
    hint.numberOfLines = 2;
    hint.text = keys.count ?
        @"判定在 UserDefaults — 左划⚡直写(Bool→YES, Date→9999) 零patch" :
        @"无语义 key — 该 app 非状态型判定, 走 F8 代码扫描";
    [page addSubview:hint];
    if (keys.count) {
        // 头部: 一键全开 + 持久化开关
        UIButton *all = [UIButton buttonWithType:UIButtonTypeSystem];
        all.frame = CGRectMake(16, 84, (g_mfCardW - 40) / 2, 38);
        [all setTitle:[NSString stringWithFormat:@"⚡全开 %lu 个", (unsigned long)keys.count] forState:UIControlStateNormal];
        [all addTarget:g_mfCtrl action:@selector(mfStateZapAll) forControlEvents:UIControlEventTouchUpInside];
        [page addSubview:all];
        // v2.58.140: 全开已自动持久化+装守卫, 旧「💾持久化」按钮冗余 → 改为「♻️全部恢复并删除」
        UIButton *per = [UIButton buttonWithType:UIButtonTypeSystem];
        per.frame = CGRectMake(16 + (g_mfCardW - 40) / 2 + 8, 84, (g_mfCardW - 40) / 2, 38);
        [per setTitle:@"♻️全部恢复并删除" forState:UIControlStateNormal];
        per.tag = 601;
        [per addTarget:g_mfCtrl action:@selector(mfStateRestoreDeleteAll:) forControlEvents:UIControlEventTouchUpInside];
        [page addSubview:per];
        g_stateList = [[MFStateList alloc] init];
        g_stateList.items = keys;
        UITableView *tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 130, g_mfCardW, g_mfCardH - 130)
                                                      style:UITableViewStylePlain];
        tv.dataSource = g_stateList;
        tv.delegate = g_stateList;
        tv.rowHeight = 58;
        tv.separatorStyle = UITableViewCellSeparatorStyleNone;
        [page addSubview:tv];
    }
    mfPushPage(page);
}
static NSString *statePrefsPath(void) {
    // /var/jb 对齐 MFAppPatch MFPrefsPath(同一文件体系), 无 /var/jb 时兜底
    return @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.state.plist";
}
static NSDictionary *stateStore(void) {
    return [NSDictionary dictionaryWithContentsOfFile:statePrefsPath()] ?: @{};
}
static void stateStoreSet(NSDictionary *d) {
    [(NSMutableDictionary *)d ?: [NSMutableDictionary dictionary] writeToFile:statePrefsPath() atomically:YES];
}
static NSString *stateWritesKey(void) {
    return [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
}
void mfStateSetPersist(NSArray *keys, BOOL on) {
    NSMutableDictionary *d = [stateStore() mutableCopy] ?: [NSMutableDictionary dictionary];
    if (on && [keys isKindOfClass:[NSArray class]] && keys.count) {
        NSMutableArray *ks = [NSMutableArray array];
        for (NSDictionary *k in keys) if (k[@"key"]) [ks addObject:k[@"key"]];
        d[stateWritesKey()] = ks;
    } else {
        [d removeObjectForKey:stateWritesKey()];
    }
    stateStoreSet(d);
    mfStateGuardInstall();   // v2.58.49: 持久化开关变化即时生效(不等冷启动)
}
void mfStateBootReplay(void) {
    NSArray *ks = stateStore()[stateWritesKey()];
    // v2.58.21: Boot 自愈 — 2.58.20 词表误命中(ServeLog 文案/URL 被⚡进 store)的
    // 垃圾条目形态不过新门, 静默清出; 剩下的才重打。防跨版本污染滚动。
    if ([ks isKindOfClass:[NSArray class]] && ks.count) {
        NSMutableArray *ok = [NSMutableArray array];
        for (NSString *k in ks) {
            if ([k isKindOfClass:[NSString class]] && stateKeyShapeOK(k)) [ok addObject:k];
            else mfLog(@"[f9] Boot 自愈: 剔除垃圾条目 %@", k);
        }
        if (ok.count < ks.count) {
            if (ok.count) { stateStoreSet(@{stateWritesKey(): ok}); }
            else { stateStoreSet(nil); }
            ks = ok;
        }
    }
    if (![ks isKindOfClass:[NSArray class]] || !ks.count) return;
    long ok = 0;
    for (NSString *k in ks) if (mfStateUnlockApplyKey(k, YES)) ok++;
    mfLog(@"[f9] Boot 状态重打: ok=%ld/%lu", ok, (unsigned long)ks.count);
    // v2.58.49: 重打之后装读侧守卫 — 写侧被 app 覆写时读侧仍是解锁值
    mfStateGuardInstall();
}
BOOL mfStatePersistIsOn(void) {
    NSArray *ks = stateStore()[stateWritesKey()];
    return [ks isKindOfClass:[NSArray class]] && ks.count;
}

// —— MFPanelCtrl action 方法(category — 页面控制器在 MFPanel.m) ——
@implementation MFPanelCtrl (StateUnlock)
- (void)mfShowStatePage { mfShowStatePage(); }
- (void)mfStateZap:(NSString *)key {
    mfStateUnlockApplyKey(key, YES);
    mfToast(@"⚡ 已直写 — 看界面是否亮");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ mfToast(@"VIP 没刷新? 回到桌面再进 app"); });
}
- (void)mfStateZapOff:(NSString *)key {
    mfStateUnlockApplyKey(key, NO);
    mfToast(@"已回滚(remove)");
}
- (void)mfStateDeleteKey:(NSString *)key {
    // v2.58.61: F9 删除 — 清侦查缓存 + 同步清持久化重打清单
    extern void mfStateReconCacheRemoveKey(NSString *);   // 本文件 mfShowStatePage 上方定义
    mfStateReconCacheRemoveKey(key);
    NSDictionary *store = [NSDictionary dictionaryWithContentsOfFile:statePrefsPath()] ?: @{};
    NSMutableArray *ks = [(store[stateWritesKey()] ?: @[]) mutableCopy];
    [ks removeObject:key];
    NSMutableDictionary *nd = [store mutableCopy];
    if (ks.count) nd[stateWritesKey()] = ks; else [nd removeObjectForKey:stateWritesKey()];
    [nd writeToFile:statePrefsPath() atomically:YES];
    mfToast(@"✂ 已删除 — 重跑侦查可恢复");
}
- (void)mfStateZapAll {
    NSArray *ks = mfStateKeysForUI();                   // 局部接住(ARC 命名桥接) — 吃侦查缓存
    long n = mfStateUnlockApplyAll(ks);
    // v2.58.138: 全开 = 写 + 持久化 + 装读侧守卫。
    //   写侧会被 app 重同步覆盖(128 铁证: 全 True 但 UI 不亮), 读侧守卫才恒返解锁值。
    //   之前全开只写不持久化 → stateGuardedKeys() 空 → 守卫从不激活(日志无"读侧守卫已装")。
    mfStateSetPersist(ks, YES);
    mfStateGuardInstall();
    mfToast([NSString stringWithFormat:@"⚡ 已直写 %ld key + 读侧守卫 %lu key", n, (unsigned long)ks.count]);
}
// v2.58.140: 全部恢复并删除 — 取代冗余的「💾持久化」按钮(全开已自动持久化)。
//   逐 key remove(标准+group 三存储回滚) + 卸读侧守卫 + 清持久化重打清单 + 清侦查缓存。
//   二次点击确认(与既有页内交互同风格, 不用系统 alert)。
- (void)mfStateRestoreDeleteAll:(UIButton *)sender {
    static CFAbsoluteTime lastTap = 0;
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (now - lastTap > 3.0) {   // 首次点: 亮起确认
        lastTap = now;
        [sender setTitle:@"⚠️再点确认恢复删除" forState:UIControlStateNormal];
        mfToast(@"再点一次: 回滚全部 key + 卸守卫 + 清库");
        return;
    }
    lastTap = 0;
    NSArray *ks = mfStateKeysForUI();
    NSUInteger n = 0;
    for (NSDictionary *d in ks) { if (d[@"key"]) { mfStateUnlockApplyKey(d[@"key"], NO); n++; } }  // remove: 三存储回滚
    // 卸读侧守卫 + 清持久化清单
    mfStateSetPersist(@[], NO);
    extern void mfStateGuardUninstall(void);
    mfStateGuardUninstall();
    // 清侦查缓存(盘+内存)
    NSMutableDictionary *sd = [stateStore() mutableCopy] ?: [NSMutableDictionary dictionary];
    [sd removeObjectForKey:stateReconCacheKey()];
    [sd removeObjectForKey:stateWritesKey()];
    stateStoreSet(sd);
    g_reconStateKeys = nil;
    [sender setTitle:@"♻️全部恢复并删除" forState:UIControlStateNormal];
    mfToast([NSString stringWithFormat:@"♻️ 已回滚 %lu key + 卸守卫 + 清库", (unsigned long)n]);
}
@end
