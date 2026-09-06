// MFSubInject.m — 订阅 SDK 响应注入 (通杀实验 v2.10.0)
// 层次定位: RevenueCat / Superwall / Adapty 云端订阅判定 → 进程内伪造 200 响应
// 与 SK1 通杀(本地交易伪造)互补——app 把订阅状态存云端时, SK1 假交易救不了, 这里救
// 商品 ID 来自 SK1 扫描列表(SavedIAPIDs), 无 per-app 硬编码
// schema 来源: Reven 网关实测(2026-08-31) + SatellaJailed ServerVerificationHooks
// v2.18.0 (Reven 逆向回流, 2026-09-02 实测):
//   1. entitlement 名自动发现——硬编码 "pro" 是盲区(Reflix 用 com.magicgroot.reflix.entitlements)
//      来源①: RC SDK NSUserDefaults 缓存 com.revenuecat.userdefaults.productEntitlementMapping
//      来源②: 主二进制字符串扫 *.entitlements 后缀标识符
//   2. lifetime 型产品进 non_subscriptions(RC 官方规范, Reven auto 策略同款), 不带 expires_date
//   2b. v2.25.0 策略化: prefs "mfSubStrategy" = auto(缺省)/lifetime_sub/year/month, 订阅产品给滚动 expires_date 进 subscriptions

#import "MFPanel.h"
#import <Foundation/Foundation.h>
#import "fishhook.h"
#import <Security/Security.h>

static BOOL g_subOn = NO;
static IMP orig_dtReq = NULL, orig_dtURL = NULL;
static long g_subHits = 0;

#pragma mark - Trusted Entitlements / 客户端验签通杀绕过

// 1. SecKeyRawVerify / SecKeyVerifySignature: 当 SDK 调用底层 Security.framework 验签时恒真放行
static OSStatus (*orig_SecKeyRawVerify)(SecKeyRef, SecPadding, const uint8_t *, size_t, const uint8_t *, size_t) = NULL;
static OSStatus my_SecKeyRawVerify(SecKeyRef key, SecPadding padding, const uint8_t *signedData, size_t signedDataLen, const uint8_t *sig, size_t sigLen) {
    if (g_subOn) {
        mfLog(@"[subinject] SecKeyRawVerify bypassed");
        return errSecSuccess;
    }
    return orig_SecKeyRawVerify ? orig_SecKeyRawVerify(key, padding, signedData, signedDataLen, sig, sigLen) : errSecSuccess;
}

static Boolean (*orig_SecKeyVerifySignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDataRef, CFErrorRef *) = NULL;
static Boolean my_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef signedData, CFDataRef signature, CFErrorRef *error) {
    if (g_subOn) {
        mfLog(@"[subinject] SecKeyVerifySignature bypassed");
        if (error) *error = NULL;
        return true;
    }
    return orig_SecKeyVerifySignature ? orig_SecKeyVerifySignature(key, algorithm, signedData, signature, error) : true;
}

static void mfInstallSecurityBypass(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        struct rebinding rebs[] = {
            {"SecKeyRawVerify", (void *)my_SecKeyRawVerify, (void **)&orig_SecKeyRawVerify},
            {"SecKeyVerifySignature", (void *)my_SecKeyVerifySignature, (void **)&orig_SecKeyVerifySignature}
        };
        rebind_symbols(rebs, sizeof(rebs) / sizeof(rebs[0]));
        mfLog(@"[subinject] Security framework signature verification rebound");
    });
}

#pragma mark - 商品 ID 源(SK1 扫描列表)

// 通用垃圾 ID 过滤(SF Symbol/设备名/内部前缀) — 非针对特定 app
BOOL mfPIDLooksReal(NSString *pid) {
    if (pid.length < 4 || pid.length > 64) return NO;
    if ([pid hasPrefix:@"mfsk1."] || [pid hasPrefix:@"X-"]) return NO;
    NSArray *junk = @[@".fill", @".badge.", @".slash", @".and.arrow", @"arrowtriangle", @"batteryblock",
                      @"square.grid", @"xmark", @"checkmark", @"questionmark", @"head.profile",
                      @"minus.plus", @"hourglass.badge", @"memories.", @"pencil.tip", @"inset.filled",
                      @"iphone-", @"iphone_", @"iPad_", @"watch-", @"beats.", @"airpods", @"homepod",
                      @"byok_", @"com.apple.", @"X-Crashlytics", @"Crashlytics",
                      @"FIRCLS", @"token", @"subscription_cancel", @"subscription_convert",
                      @"subscription_renew", @"app_upgrade", @"badge.plus", @"_ACv", @"Pro_129", @"Mac_"];
    for (NSString *p in junk) if ([pid containsString:p]) return NO;
    // 保留条件: 含点(反向域名/命名空间) 或 带下划线的语义短语
    if (![pid containsString:@"."] && ![pid containsString:@"_"]) return NO;
    return YES;
}

// v2.11.8: 文件级 ID 存储 — NSUserDefaults 会被 app 抹掉(实测 07:00 写 07:02 空), 自己的文件自己守
static NSString *mfIAPIDsFilePath(void) {
    static NSString *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *sub = [dir stringByAppendingPathComponent:@"MinisFix"];
        [[NSFileManager defaultManager] createDirectoryAtPath:sub withIntermediateDirectories:YES attributes:nil error:NULL];
        p = [sub stringByAppendingPathComponent:@"iapids.plist"];
    });
    return p;
}
static NSMutableArray *g_fileIDs = nil;
static dispatch_semaphore_t g_fileSem = NULL;
static NSArray *mfFileIDsRead(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ g_fileSem = dispatch_semaphore_create(1); });
    dispatch_semaphore_wait(g_fileSem, DISPATCH_TIME_FOREVER);
    if (!g_fileIDs) g_fileIDs = [[NSArray arrayWithContentsOfFile:mfIAPIDsFilePath()] ?: @[] mutableCopy];
    dispatch_semaphore_signal(g_fileSem);
    return g_fileIDs ?: @[];
}
void mfFileIDsAdd(NSString *pid) { // 高置信插头部; MFPanel.m 调用
    if (pid.length == 0 || pid.length > 100) return;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ mfFileIDsRead(); });
    dispatch_semaphore_wait(g_fileSem, DISPATCH_TIME_FOREVER);
    if (![g_fileIDs containsObject:pid]) {
        [g_fileIDs removeObject:pid];
        [g_fileIDs insertObject:pid atIndex:0];
        if (g_fileIDs.count > 200) [g_fileIDs removeObjectsInRange:NSMakeRange(200, g_fileIDs.count - 200)];
        [g_fileIDs writeToFile:mfIAPIDsFilePath() atomically:YES];
        mfLog(@"[iap] file id: %@ (total %lu)", pid, (unsigned long)g_fileIDs.count);
    }
    dispatch_semaphore_signal(g_fileSem);
}

// v2.11.10: 沙盒指纹 — Documents 路径含容器 UUID, 两份日志一对比就知道是不是同一个安装
void mfFileIDsDiag(void) {
    NSArray *a = mfFileIDsRead();
    mfLog(@"[MF] sandbox doc=%@ file_ids=%lu", mfIAPIDsFilePath(), (unsigned long)a.count);
}

NSArray *mfSubPids(void) { // 非 static: MFReceiptForge.m 共用
    // v2.11.8: 文件存储为主, NSUserDefaults(mfTopIDs/SavedIAPIDs)作迁移兜底
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSArray *top = [d objectForKey:@"mfTopIDs"] ?: @[];
    NSArray *rest = [d objectForKey:@"SavedIAPIDs"] ?: @[];
    NSMutableArray *clean = [NSMutableArray array];
    static int diagLogged = 0;   // v2.12.0: 每进程前 2 次调用打全量诊断
    int doDiag = diagLogged < 2; if (doDiag) diagLogged++;
    for (NSString *pid in [mfFileIDsRead() arrayByAddingObjectsFromArray:[top arrayByAddingObjectsFromArray:rest]]) {
        if (![pid isKindOfClass:[NSString class]]) { if (doDiag) mfLog(@"[mfsubpids] drop nonstring %@", [pid class]); continue; }
        if (!mfPIDLooksReal(pid)) { if (doDiag) mfLog(@"[mfsubpids] filter kill %@", pid); continue; }
        if ([clean containsObject:pid]) continue;
        // JSON 安全: 剥引号/反斜杠/控制符 (v2.12.1 修复: 按 controlCharacterSet 切分去控制符,
        // 之前误用 invertedSet = 按正常字符切分 = 所有 ID 被洗成空串 = clean 恒 0 = 恒 fallback)
        NSString *s = [pid stringByReplacingOccurrencesOfString:@"\"" withString:@""];
        s = [s stringByReplacingOccurrencesOfString:@"\\" withString:@""];
        NSCharacterSet *bad = [NSCharacterSet controlCharacterSet];
        s = [[s componentsSeparatedByCharactersInSet:bad] componentsJoinedByString:@""];
        if (s.length && s.length <= 200) [clean addObject:s];
    }
    if (doDiag) {
        NSArray *fid = mfFileIDsRead();
        mfLog(@"[mfsubpids] file=%lu top=%lu rest=%lu clean=%lu first=%@",
              (unsigned long)fid.count, (unsigned long)top.count, (unsigned long)rest.count,
              (unsigned long)clean.count, clean.firstObject ?: @"-");
        for (NSString *p in fid) if (doDiag) mfLog(@"[mfsubpids] file item: %@", p);
    }
    if (clean.count) return clean;
    return @[@"com.mf.premium.lifetime"];
}

static NSString *mfSubNowISO(void) {
    static NSISO8601DateFormatter *f = nil;
    if (!f) { f = [NSISO8601DateFormatter new]; f.formatOptions = NSISO8601DateFormatWithInternetDateTime; }
    return [f stringFromDate:[NSDate date]];
}

#pragma mark - 目标匹配(host 白名单制, 不做关键词 shotgun)

static BOOL mfSubIsRCHost(NSString *h) {
    if ([h isEqualToString:@"api.revenuecat.com"] || [h isEqualToString:@"api.rc-backup.com"]) return YES;
    // v2.23.2: RC 反代盲区 — rc.*/revenue.* 前缀的自建反代同协议
    if ([h hasPrefix:@"rc."] || [h hasPrefix:@"revenue."]) return YES;
    return NO;
}

static BOOL mfSubIsTarget(NSURL *u) {
    if (!u.host) return NO;
    NSString *h = u.host.lowercaseString, *p = u.path ?: @"";
    if (mfSubIsRCHost(h)) {
        // v2.18.1: /offerings 是产品目录 + offline entitlements 映射(SDK5 SK2 模式靠它本地算 entitlements),
        // 吞掉 = 目录加载报废 + 离线映射永不缓存 + 自家 mfprobe 扫描被打死(Reflix 实录), 只放行 subscribers GET 与 receipts POST
        if ([p containsString:@"/offerings"]) return NO;
        return [p containsString:@"/subscribers"] || [p hasSuffix:@"/receipts"];
    }
    if ([h isEqualToString:@"subscriptions-api.superwall.com"])
        return YES; // SW SDK 的 session/events 响应均携带 entitlement 数据
    if ([h isEqualToString:@"api.adapty.io"] || [h isEqualToString:@"api-backup.adapty.io"])
        return [p containsString:@"/in-apps"] || [p containsString:@"/profiles"] || [p containsString:@"/purchase"];
    // v2.11.0: 客户端直调 verifyReceipt 的老 app
    if ([h isEqualToString:@"buy.itunes.apple.com"] || [h isEqualToString:@"sandbox.itunes.apple.com"])
        return [p hasSuffix:@"/verifyReceipt"];
    return NO;
}

#pragma mark - v2.18.0: entitlement 名自动发现(Reven 逆向回流)

// 来源①: RC SDK 自己把映射缓存在 NSUserDefaults(进程内直接读)
static NSArray *mfEntsFromRCCache(void) {
    NSMutableArray *out = [NSMutableArray array];
    @try {
        NSDictionary *m = [[NSUserDefaults standardUserDefaults]
            dictionaryForKey:@"com.revenuecat.userdefaults.productEntitlementMapping"];
        for (NSString *pid in m) {
            id v = m[pid];
            NSArray *ents = nil;
            if ([v isKindOfClass:[NSString class]]) ents = @[v];
            else if ([v isKindOfClass:[NSArray class]]) ents = v;
            for (NSString *e in ents)
                if ([e isKindOfClass:[NSString class]] && e.length && ![out containsObject:e]) [out addObject:e];
        }
    } @catch (NSException *e) {}
    return out;
}

// 来源②: 主二进制扫 "...entitlements" 标识符(Reflix 实测: com.magicgroot.reflix.entitlements)
static NSArray *mfEntsFromBinaryScan(void) {
    NSMutableArray *out = [NSMutableArray array];
    @try {
        NSData *d = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] executablePath]];
        if (!d || d.length > 200 * 1024 * 1024) return out;
        NSString *s = [[NSString alloc] initWithData:d encoding:NSASCIIStringEncoding];
        if (!s) return out;
        NSError *err = nil;
        NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:
            @"[a-z0-9][a-z0-9.-]{2,80}\\.entitlements" options:0 error:&err];
        for (NSTextCheckingResult *r in [re matchesInString:s options:0 range:NSMakeRange(0, s.length)]) {
            NSString *e = [s substringWithRange:r.range];
            if ([e hasPrefix:@"com.apple."]) continue;
            if (![out containsObject:e]) [out addObject:e];
            if (out.count >= 8) break;
        }
    } @catch (NSException *e) {}
    return out;
}

static NSArray *mfDiscoveredEntitlements(void) {
    static NSArray *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSMutableArray *all = [NSMutableArray array];
        for (NSString *e in mfEntsFromRCCache()) if (![all containsObject:e]) [all addObject:e];
        for (NSString *e in mfEntsFromBinaryScan()) if (![all containsObject:e]) [all addObject:e];
        cached = all;   // 可为空 → 调用方回退 "pro"
        mfLog(@"[subinject] ents discovered: %@", cached);
    });
    return cached;
}

// lifetime 型产品判定(Reven auto 策略: lifetime 不进 subscriptions, 进 non_subscriptions)
static BOOL mfPIDLooksLifetime(NSString *pid) {
    NSString *p = pid.lowercaseString;
    return [p containsString:@"lifetime"] || [p containsString:@"forever"]
        || [p containsString:@"one_time"] || [p containsString:@"onetime"]
        || [p containsString:@"one-time"] || [p containsString:@"perpetual"];
}

// v2.25.0: 滚动过期时间(订阅形态) = now+周期, RFC3339 秒级(对齐定版样本日期格式)
static NSString *mfSubISOFuture(NSTimeInterval dt) {
    static NSISO8601DateFormatter *f = nil;
    if (!f) { f = [NSISO8601DateFormatter new]; f.formatOptions = NSISO8601DateFormatWithInternetDateTime; }
    return [f stringFromDate:[NSDate dateWithTimeIntervalSinceNow:dt]];
}

#pragma mark - 响应构造

static NSString *mfSubJSON(NSURL *u) {
    NSString *h = u.host.lowercaseString;
    NSArray *pids = mfSubPids();
    __unused NSString *pid0 = pids.firstObject;   // SW/Adapty/VR 分支仍用
    NSString *now = mfSubNowISO();
    __unused NSString *far = @"2099-09-09T09:09:09Z";

    if (mfSubIsRCHost(h)) {
        // v2.24.1 最小骨架(RC SDK 逐字段核对) + v2.25.0 expires_date 策略化:
        //   auto         = 有 lifetime 产品→lifetime 形态(9字段定版); 无→订阅形态(产品进 subscriptions, expires_date 按周期滚动)
        //   lifetime_sub = 强制 lifetime 形态(订阅产品也给 expires_date null=永不过期)
        //   year/month   = 强制订阅形态, 固定滚动 +1年/+1月
        // 覆盖键: 进程 prefs "mfSubStrategy"(defaults write <bundleid> mfSubStrategy month), 缺省 auto
        NSString *strategy = [[NSUserDefaults standardUserDefaults] stringForKey:@"mfSubStrategy"];
        if (!strategy.length) strategy = @"auto";
        NSArray *ents = mfDiscoveredEntitlements();
        if (!ents.count) ents = @[@"pro"];
        NSString *lifePID = nil;
        for (NSString *pid in pids) if (mfPIDLooksLifetime(pid)) { lifePID = pid; break; }
        // 订阅产品挑选: 周期越长优先(年>月>周), 决定 auto 滚动步长
        NSString *subPID = nil; int subScore = -1;
        for (NSString *pid in pids) {
            NSString *p = pid.lowercaseString;
            int sc = ([p containsString:@"year"] || [p containsString:@"annual"]) ? 3
                   : ([p containsString:@"week"]) ? 1 : 2;
            if (sc > subScore) { subScore = sc; subPID = pid; }
        }
        if (!subPID) subPID = pids.firstObject ?: @"com.mf.premium.monthly";
        BOOL subShape = [strategy isEqualToString:@"year"] || [strategy isEqualToString:@"month"]
                      || (![strategy isEqualToString:@"lifetime_sub"] && !lifePID);
        NSTimeInterval step = [strategy isEqualToString:@"year"] ? (NSTimeInterval)366*86400
                            : [strategy isEqualToString:@"month"] ? (NSTimeInterval)31*86400
                            : subScore == 3 ? (NSTimeInterval)366*86400
                            : subScore == 1 ? (NSTimeInterval)7*86400
                            : (NSTimeInterval)31*86400;
        NSString *bindPID = subShape ? subPID : (lifePID ?: (pids.firstObject ?: @"com.mf.premium.lifetime"));
        mfLog(@"[subinject] strategy=%@ shape=%@ pid=%@ step=%.0fs",
              strategy, subShape ? @"subscription" : @"lifetime", bindPID, step);
        // 回显 uid: subscribers/<uid> 路径
        NSString *uid = @"mf-user";
        NSString *path = u.path ?: @"";
        NSRange r = [path rangeOfString:@"/v1/subscribers/"];
        if (r.location != NSNotFound) {
            NSString *rest = [path substringFromIndex:NSMaxRange(r)];
            NSUInteger slash = [rest rangeOfString:@"/"].location;
            if (slash != NSNotFound) rest = [rest substringToIndex:slash];
            if (rest.length >= 8 && rest.length <= 200) uid = rest;
        }
        // Reven 风格时间: 带毫秒
        NSString *nowMs = [NSString stringWithFormat:@"%@.%03lldZ",
                           [now substringToIndex:now.length - 1],
                           (long long)([[NSDate date] timeIntervalSince1970] * 1000) % 1000];
        NSMutableString *ent = [NSMutableString string];
        for (NSString *e in ents) {
            NSString *exp = subShape ? [NSString stringWithFormat:@"\"%@\"", mfSubISOFuture(step)] : @"null";
            [ent appendFormat:@"%@\"%@\":{\"is_sandbox\":false,\"ownership_type\":\"PURCHASED\",\"store\":\"app_store\",\"original_purchase_date\":\"2021-11-21T17:32:12Z\",\"purchase_date\":\"2021-11-21T17:32:12Z\",\"expires_date\":%@,\"product_identifier\":\"%@\"}",
             ent.length ? @"," : @"", e, exp, bindPID];
        }
        NSString *body;
        if (!subShape) {
            // lifetime 形态 = v2.24.5 定版 9 字段(实测亮, 不动)
            NSString *nonSubs = [NSString stringWithFormat:
                @"\"%@\":[{\"id\":\"lifetime_%@\",\"is_sandbox\":false,\"original_purchase_date\":\"2021-11-21T17:32:12Z\",\"purchase_date\":\"2021-11-21T17:32:12Z\",\"store\":\"app_store\",\"store_transaction_id\":\"lifetime_%@\"}]",
                bindPID, bindPID, bindPID];
            body = [NSString stringWithFormat:
                @"{\"request_date\":\"%@\",\"subscriber\":{"
                @"\"entitlements\":{%@},"
                @"\"non_subscriptions\":{%@},"
                @"\"first_seen\":\"2024-06-10T11:12:09Z\","
                @"\"original_app_user_id\":\"%@\"}}",
                nowMs, ent, nonSubs, uid];
        } else {
            // 订阅形态: expires_date 滚动未来 + 产品进 subscriptions(RC 订阅规范位), 无 non_subscriptions
            NSString *subs = [NSString stringWithFormat:
                @"\"%@\":{\"expires_date\":\"%@\",\"original_purchase_date\":\"2021-11-21T17:32:12Z\",\"purchase_date\":\"2021-11-21T17:32:12Z\",\"store\":\"app_store\",\"is_sandbox\":false,\"ownership_type\":\"PURCHASED\",\"period_type\":\"normal\",\"auto_renew_status\":true}",
                bindPID, mfSubISOFuture(step)];
            body = [NSString stringWithFormat:
                @"{\"request_date\":\"%@\",\"subscriber\":{"
                @"\"entitlements\":{%@},"
                @"\"subscriptions\":{%@},"
                @"\"first_seen\":\"2024-06-10T11:12:09Z\","
                @"\"original_app_user_id\":\"%@\"}}",
                nowMs, ent, subs, uid];
        }
        return body;
    }

    if ([h isEqualToString:@"subscriptions-api.superwall.com"]) {
        NSMutableString *parr = [NSMutableString string];
        for (NSString *pid in pids)
            [parr appendFormat:@"%@\"%@\"", parr.length ? @"," : @"", pid];
        return [NSString stringWithFormat:
            @"{\"entitlements\":[\"pro\"],\"customerInfo\":{\"subscriptions\":[],\"nonSubscriptions\":[],"
            @"\"entitlements\":[{\"identifier\":\"pro\",\"type\":\"SERVICE_LEVEL\",\"isActive\":true,"
            @"\"productIds\":[%@],\"isLifetime\":true,\"willRenew\":true,\"startsAt\":\"%@\",\"expiresAt\":\"%@\"}]}}",
            parr, now, far];
    }

    // v2.11.0: Apple verifyReceipt JSON(in_app 来自扫描列表)
    if ([h isEqualToString:@"buy.itunes.apple.com"] || [h isEqualToString:@"sandbox.itunes.apple.com"]) {
        NSMutableString *inApp = [NSMutableString string];
        long long i = 0;
        for (NSString *pid in pids) {
            [inApp appendFormat:@"%@{\"quantity\":\"1\",\"product_id\":\"%@\",\"transaction_id\":\"mfsk1.vr.%lld\","
             @"\"original_transaction_id\":\"mfsk1.vr.%lld\",\"purchase_date\":\"%@\",\"original_purchase_date\":\"%@\","
             @"\"expires_date\":\"2099-09-09T09:09:09Z\",\"is_trial_period\":\"false\"}",
             inApp.length ? @"," : @"", pid, i, i, now, now];
            i++;
        }
        return [NSString stringWithFormat:
            @"{\"status\":0,\"environment\":\"Production\","
            @"\"receipt\":{\"receipt_type\":\"Production\",\"adam_id\":100000,\"app_item_id\":100000,"
            @"\"bundle_id\":\"%@\",\"application_version\":\"%@\",\"download_id\":100000,"
            @"\"version_external_identifier\":0,\"original_application_version\":\"1.0\","
            @"\"request_date\":\"%@\",\"receipt_creation_date\":\"%@\",\"original_purchase_date\":\"%@\","
            @"\"in_app\":[%@]},"
            @"\"latest_receipt_info\":[%@],"
            @"\"pending_renewal_info\":[{\"auto_renew_product_id\":\"%@\",\"product_id\":\"%@\","
            @"\"original_transaction_id\":\"mfsk1.vr.0\",\"auto_renew_status\":\"1\"}],"
            @"\"latest_receipt\":\"mfsk1-blob\"}",
            [NSBundle mainBundle].bundleIdentifier ?: @"com.mf.unknown",
            [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"1.0",
            now, now, now, inApp, inApp, pids.firstObject ?: @"com.mf.product", pids.firstObject ?: @"com.mf.product"];
    }

    // Adapty
    return [NSString stringWithFormat:
        @"{\"profile_id\":\"mf-user\",\"access_levels\":{\"premium\":{\"id\":\"premium\",\"isActive\":true,"
        @"\"will_renew\":true,\"is_lifetime\":true,\"vendor_product_id\":\"%@\",\"store\":\"app_store\","
        @"\"starts_at\":\"%@\",\"expires_at\":\"%@\",\"renewed_at\":\"%@\"}},"
        @"\"subscriptions\":{\"%@\":{\"vendor_product_id\":\"%@\",\"store\":\"app_store\",\"is_active\":true,"
        @"\"is_lifetime\":true,\"expires_at\":\"%@\"}},\"non_subscriptions\":{},\"is_active\":true}",
        pid0, now, far, far, pid0, pid0, far];
}

#pragma mark - Hook(包装 completionHandler, 网络照发, 响应替换)

typedef id (*DTReqIMP)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef id (*DTURLIMP)(id, SEL, NSURL *, void (^)(NSData *, NSURLResponse *, NSError *));

static void mfSubDeliver(NSURL *u, void (^h)(NSData *, NSURLResponse *, NSError *)) {
    g_subHits++;
    NSString *json = mfSubJSON(u);
    NSData *d = [json dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *headers = @{
        @"Content-Type": @"application/json",
        @"X-RevenueCat-ETag": @"\"mf-etag-2099\"",
        @"X-Platform": @"iOS"
    };
    NSHTTPURLResponse *r = [[NSHTTPURLResponse alloc] initWithURL:u statusCode:200
                                                     HTTPVersion:@"HTTP/1.1"
                                                 headerFields:headers];
    mfLog(@"[subinject] #%ld mock %@%@", g_subHits, u.host, u.path);
    h(d, r, nil);
}

static id mf_dtReq(id self, SEL _cmd, NSURLRequest *req, void (^handler)(NSData *, NSURLResponse *, NSError *)) {
    if (!g_subOn || !handler || !req.URL || !mfSubIsTarget(req.URL))
        return ((DTReqIMP)orig_dtReq)(self, _cmd, req, handler);
    NSURL *u = req.URL;
    return ((DTReqIMP)orig_dtReq)(self, _cmd, req, ^(NSData *d, NSURLResponse *r, NSError *e) {
        mfSubDeliver(u, handler); // 吞掉真实响应
    });
}

static id mf_dtURL(id self, SEL _cmd, NSURL *u, void (^handler)(NSData *, NSURLResponse *, NSError *)) {
    if (!g_subOn || !handler || !u || !mfSubIsTarget(u))
        return ((DTURLIMP)orig_dtURL)(self, _cmd, u, handler);
    return ((DTURLIMP)orig_dtURL)(self, _cmd, u, ^(NSData *d, NSURLResponse *r, NSError *e) {
        mfSubDeliver(u, handler);
    });
}

#pragma mark - 开关/持久化

void mfSubInjectEnable(void) {
    if (g_subOn) return;
    mfInstallSecurityBypass();
    Class c = [NSURLSession class];
    Method m1 = class_getInstanceMethod(c, @selector(dataTaskWithRequest:completionHandler:));
    Method m2 = class_getInstanceMethod(c, @selector(dataTaskWithURL:completionHandler:));
    if (!m1 || !m2) { mfLog(@"[subinject] hook fail: selector missing"); return; }
    orig_dtReq = method_setImplementation(m1, (IMP)mf_dtReq);
    orig_dtURL = method_setImplementation(m2, (IMP)mf_dtURL);
    g_subOn = YES;
    mfLog(@"[subinject] hooks ON");
}

void mfSubInjectDisable(void) {
    if (!g_subOn) return;
    Class c = [NSURLSession class];
    Method m1 = class_getInstanceMethod(c, @selector(dataTaskWithRequest:completionHandler:));
    Method m2 = class_getInstanceMethod(c, @selector(dataTaskWithURL:completionHandler:));
    if (m1 && orig_dtReq) method_setImplementation(m1, orig_dtReq);
    if (m2 && orig_dtURL) method_setImplementation(m2, orig_dtURL);
    orig_dtReq = orig_dtURL = NULL;
    g_subOn = NO;
    mfLog(@"[subinject] hooks OFF");
}

void mfSubInjectSwitchChanged(UISwitch *sw) {
    if (sw.on) { mfSubInjectEnable(); mfToast(@"📡 订阅 SDK 注入已开启"); }
    else { mfSubInjectDisable(); mfToast(@"⏹️ 订阅 SDK 注入已关闭"); }
    [[NSUserDefaults standardUserDefaults] setBool:sw.on forKey:@"mfSubInjectEnabled"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

void mfSubInjectAutoStart(void) {
    if (![[NSUserDefaults standardUserDefaults] boolForKey:@"mfSubInjectEnabled"]) return;
    mfSubInjectEnable();
}

long mfSubInjectHits(void) { return g_subHits; }
BOOL mfSubInjectIsOn(void) { return g_subOn; }
