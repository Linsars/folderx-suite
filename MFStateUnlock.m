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
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import "MFPanel.h"

// 跨文件接口(MFRecon 调侦查 / ctor 调重打)
NSArray *mfStateProbeKeys(void);
void mfStateBootReplay(void);
BOOL mfStatePersistIsOn(void);
void mfStateSetPersist(NSArray *keys, BOOL on);

// MFPanelCtrl 定义在 MFPanel.m — 最小前向声明让 category 可编译(MFAppPatch.m 同款)
@interface MFPanelCtrl : NSObject @end
// 声明段在前(UI 块的 [(id)g_mfCtrl mfStateZap:] 需要它), 实现段在本文件尾部
@interface MFPanelCtrl (StateUnlock)
- (void)mfShowStatePage;
- (void)mfStateZap:(NSString *)key;
- (void)mfStateZapOff:(NSString *)key;
- (void)mfStateZapAll;
- (void)mfStatePersistToggle:(UIButton *)sender;
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
    if (segs.count < 2) return NO;                               // 纯单词不是 plist key 风格
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
    if (![k containsString:@"."]) return NO;    // plist key 命名风格: a.b 点分 camelCase
    if ([k hasPrefix:@"com."]) return NO;       // 排除第三方 SDK 域名风格 key(RC 映射等 — 缓存 dict, 直写会破坏)
    if (!stateKeyShapeOK(k)) return NO;         // v2.58.21: 形态门 — 文案/URL/路径不是 key
    // v2.58.35: 静态污染排除(Reflix 76 假案定谳) — __cstring 里的 i18n 文案段
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
        // 运行时实存 key 兜底(app 写过/读过的全在) — 语义过滤后并入
        NSDictionary *live = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        for (NSString *k in live.allKeys)
            if (stateKeyMatch(k)) [cand addObject:k];
        NSMutableArray *out = [NSMutableArray array];
        for (NSString *k in [cand allObjects]) {
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
    if (!on) {
        [ud removeObjectForKey:key];
        [ud synchronize];
        mfLog(@"[f9] ⚡状态直写 %@ = remove → (已删)", key);
        return 1;
    }
    // v2.58.47: 反向语义词表 — missing/lost/revok 类 key **存在本身 = 锁定态**,
    //   写 YES/distantFuture 恰好强化"缺失中"(mf_debug_50: missingSince 写 YES 不亮)。
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
            [ud removeObjectForKey:key];
            [ud synchronize];
            mfLog(@"[f9] ⚡状态直写 %@ = REMOVE(反向语义词 %@ — 存在=锁定, 删=解锁)", key, w);
            return 1;
        }
    }
    // v2.58.47: 容器类型跳过 — records/transactions 类 key 实存 dict/array,
    //   写 Bool 毁类型, app 解析失败等于白写(mf_debug_50: verifiedRecords 写 YES 不亮)。
    //   记录集无法凭空伪造 — 该 app 解锁走 F8 代码点位(8 个尾and 判定尾巴)。
    id cur = [ud objectForKey:key];
    if (cur && ([cur isKindOfClass:[NSDictionary class]] || [cur isKindOfClass:[NSArray class]])) {
        mfLog(@"[f9] ⚡状态直写 %@ 跳过 — 实存类型 %@(容器记录集, 伪造无意义)", key, NSStringFromClass([cur class]));
        return 1;
    }
    if (stateKeyIsDate(key)) {
        // distantFuture = 9999-12-31 — Date 比较恒成立
        [ud setObject:[NSDate distantFuture] forKey:key];
    } else {
        [ud setBool:YES forKey:key];
    }
    [ud synchronize];
    id after = [ud objectForKey:key];
    mfLog(@"[f9] ⚡状态直写 %@ = %@ → %@ (落盘类型:%@)", key, on ? @"YES/distantFuture" : @"remove",
          [after description], after ? NSStringFromClass([after class]) : @"nil");
    return 1;
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
// 左划: ⚡直写(橙) / 回滚(灰)
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSString *key = self.items[ip.row][@"key"];
    UIContextualAction *zap = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"⚡直写" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [(id)g_mfCtrl mfStateZap:key];
            done(YES);
        }];
    zap.backgroundColor = [UIColor systemOrangeColor];
    UIContextualAction *rev = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleDestructive
        title:@"回滚" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [(id)g_mfCtrl mfStateZapOff:key];
            done(YES);
        }];
    rev.backgroundColor = [UIColor systemGrayColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[zap, rev]];
}
@end
static MFStateList *g_stateList = nil;

// v2.58.35: 侦查=唯一采集器(用户架构定案) — recon 采集的 stateKeys 缓存于此, F9
//   全部消费点只读缓存; 缓存空(未跑过侦查)时回退原 mfStateProbeKeys()(保 UI 不空,
//   但定性只认侦查卡)。缓存带 ts, 冷启动过期(数据是侦查时快照)。
static NSArray *g_reconStateKeys = nil;
void mfStateReconCacheSet(NSArray *keys) {
    g_reconStateKeys = [keys copy];
}
NSArray *mfStateKeysForUI(void) {
    if (g_reconStateKeys.count) return g_reconStateKeys;
    return mfStateProbeKeys();   // 兜底: 没跑侦查直接开 F9(不推荐, 侦查卡才是定性者)
}

void mfShowStatePage(void) {
    UIView *page = mfMakePage(@"🔓 状态解锁 F9", YES);
    NSArray *keys = mfStateKeysForUI();
    mfLog(@"[f9] 侦查: %lu 个语义 key%@ (源: %@)", (unsigned long)keys.count, keys.count ? @"" : @"(无 — 该 app 非状态型判定)",
        g_reconStateKeys.count ? @"侦查卡缓存" : @"F9 兜底独立扫(未跑侦查)");
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
        UIButton *per = [UIButton buttonWithType:UIButtonTypeSystem];
        per.frame = CGRectMake(16 + (g_mfCardW - 40) / 2 + 8, 84, (g_mfCardW - 40) / 2, 38);
        [per setTitle:mfStatePersistIsOn() ? @"💾持久化 ON(冷启动重打)" : @"💾持久化(冷启动重打)" forState:UIControlStateNormal];
        per.tag = 601;
        [per addTarget:g_mfCtrl action:@selector(mfStatePersistToggle:) forControlEvents:UIControlEventTouchUpInside];
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
- (void)mfStateZapAll {
    NSArray *ks = mfStateKeysForUI();                   // 局部接住(ARC 命名桥接) — 吃侦查缓存
    long n = mfStateUnlockApplyAll(ks);
    mfToast([NSString stringWithFormat:@"⚡ 已直写 %ld 个 key", n]);
}
- (void)mfStatePersistToggle:(UIButton *)sender {
    BOOL now = mfStatePersistIsOn();
    NSArray *ks = mfStateKeysForUI();                   // 局部接住(ARC 命名桥接) — 吃侦查缓存
    mfStateSetPersist(ks, !now);
    sender.titleLabel.text = !now ? @"💾持久化 ON(冷启动重打)" : @"💾持久化(冷启动重打)";
    mfToast(!now ? @"💾 冷启动自动重打已开" : @"已取消持久化");
}
@end
