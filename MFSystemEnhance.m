// MFSystemEnhance.m — 系统增强(仅 SpringBoard 进程,由 MFPanel ctor 定向激活)
// ⚡ 充电限制: IOKit IOPMPowerSource 注册表直写(SB 本身 root,无需子进程)
//    机制来源: LimitCharging(com.zqbb.limitcharging) 逆向确认——IsCharging/PredictiveChargingInhibit
// 📶 Wi-Fi 永连: SBBacklightController allowIdleSleep → NO(阻止空闲睡眠=待机不断网)
// 设计: 开关实时读偏好,改设置即时生效,免 respring

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach/mach.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define SE_PREFS @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"

static NSDictionary *sePrefs(void) {
    return [NSDictionary dictionaryWithContentsOfFile:SE_PREFS] ?: @{};
}

#pragma mark - IOKit 直写(dlsym 零头文件依赖)

typedef mach_port_t se_io_t;
static kern_return_t (*p_IOMasterPort)(mach_port_t, mach_port_t *);
static CFMutableDictionaryRef (*p_IOServiceMatching)(const char *);
static se_io_t (*p_IOServiceGetMatchingService)(mach_port_t, CFMutableDictionaryRef);
static kern_return_t (*p_IORegistryEntrySetCFProperties)(se_io_t, CFTypeRef);
static kern_return_t (*p_IOObjectRelease)(se_io_t);
static kern_return_t (*p_IORegistryEntryCreateCFProperties)(se_io_t, CFMutableDictionaryRef *, CFAllocatorRef, UInt32);

static BOOL seLoadIOKit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlsym(RTLD_DEFAULT, "IOMasterPort");
        if (!h) h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        if (!h) return;
        p_IOMasterPort = dlsym(RTLD_DEFAULT, "IOMasterPort");
        p_IOServiceMatching = dlsym(RTLD_DEFAULT, "IOServiceMatching");
        p_IOServiceGetMatchingService = dlsym(RTLD_DEFAULT, "IOServiceGetMatchingService");
        p_IORegistryEntrySetCFProperties = dlsym(RTLD_DEFAULT, "IORegistryEntrySetCFProperties");
        p_IOObjectRelease = dlsym(RTLD_DEFAULT, "IOObjectRelease");
        p_IORegistryEntryCreateCFProperties = dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperties");
        if (!p_IOMasterPort || !p_IOServiceMatching || !p_IOServiceGetMatchingService ||
            !p_IORegistryEntrySetCFProperties || !p_IOObjectRelease) {
            NSLog(@"[SysEnhance] IOKit symbols missing");
        }
    });
    return p_IOMasterPort != NULL;
}

// v2.6.19: SB 进程无 IAPtools 面板,决策日志双写固定文件(Filza/SSH 直接看)
// 上限 32KB,超过砍半防无限增长
static void seFileLog(NSString *line) {
    static NSString *path = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        path = @"/var/mobile/Documents/minisfix_sysenhance.log";
    });
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSDictionary *attr = [fm attributesOfItemAtPath:path error:nil];
        if ([attr fileSize] > 32768) { // 砍半续命
            NSString *old = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
            if (old.length > 4096)
                [[old substringFromIndex:old.length - 16384] writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) { [@"" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]; fh = [NSFileHandle fileHandleForWritingAtPath:path]; }
        if (fh) { [fh seekToEndOfFile]; [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    } @catch (NSException *e) {}
}

// on=YES 恢复充电 / NO=停充
// v2.6.20: 三处对齐 lich4/ChargeLimiter 源码:
//   ① iOS>=13 键语义: IsCharging 恒 YES,PredictiveChargingInhibit 才是总开关(旧写法是 iOS12 的)
//   ② PowerUISmartChargeClient.disableSmartCharging 关掉系统优化充电(卡80%元凶)
//   ③ ExternalConnected 同步消除 120s 决策延迟并刷新充电图标
// v2.6.27: 全面诊断版——client 创建失败/查询状态/调用 err 全部落盘,失败可重试
// 对标 ChargeLimiter utils.mm getSmartChargeClient/isSmartChargeEnable
static id seSmartClient(void) {
    static id client = nil;
    if (client) return client;
    NSBundle *b = [NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/PowerUI.framework"];
    if (!b) { NSLog(@"[SysEnhance] PowerUI.framework not found"); return nil; }
    [b load];
    Class cls = objc_getClass("PowerUISmartChargeClient");
    if (!cls) { NSLog(@"[SysEnhance] PowerUISmartChargeClient class missing"); return nil; }
    client = [[cls alloc] performSelector:NSSelectorFromString(@"initWithClientName:") withObject:@"Settings"];
    return client;
}

// 返回: -1 查询失败 / 0 disable / 1 enable / 2 fullcharge / 3 temporarily_disable (ChargeLimiter 语义)
static int seSmartQuery(void) {
    id client = seSmartClient();
    if (!client) return -1;
    SEL sel = NSSelectorFromString(@"isSmartChargingCurrentlyEnabled:");
    if (![client respondsToSelector:sel]) {
        seFileLog(@"[smart] isSmartChargingCurrentlyEnabled: selector missing");
        return -1;
    }
    NSError *err = nil;
    int status = ((int(*)(id,SEL,NSError**))objc_msgSend)(client, sel, &err);
    if (err) NSLog(@"[SysEnhance] smart query err=%@", err);
    return status;
}

// v2.6.28: 充电链路关键键落盘——区分软件 inhibit vs 物理CV涓流
// v2.6.29: 两个 service 各读一份,验证直写到底在哪个 service 生效
static void seDumpBatteryKeys(NSString *tag) {
    if (!seLoadIOKit() || !p_IORegistryEntryCreateCFProperties) return;
    mach_port_t master = 0;
    p_IOMasterPort(0, &master);
    const char *names[] = {"AppleSmartBattery", "IOPMPowerSource"};
    NSArray *keys = @[@"ExternalConnected", @"IsCharging", @"ExternalChargeCapable",
        @"PredictiveChargingInhibit", @"InflowOverride", @"AtCritical", @"FullyCharged",
        @"CurrentCapacity", @"AppleRawCurrentCapacity", @"MaxCapacity",
        @"InstantAmperage", @"Amperage", @"Voltage", @"Temperature",
        @"BatteryThermalState", @"ChargingInhibited", @"AdapterDetails"];
    for (int i = 0; i < 2; i++) {
        se_io_t svc = p_IOServiceGetMatchingService(master, p_IOServiceMatching(names[i]));
        if (!svc) continue;
        CFMutableDictionaryRef props = NULL;
        if (p_IORegistryEntryCreateCFProperties(svc, &props, kCFAllocatorDefault, 0) == 0 && props) {
            NSDictionary *d = (__bridge_transfer NSDictionary *)props;
            // v2.6.33: dump 必须带时间戳——无时间的温度数据无法对齐"卡住瞬间"
            NSString *ts = [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                          dateStyle:NSDateFormatterNoStyle
                                                          timeStyle:NSDateFormatterMediumStyle];
            seFileLog([NSString stringWithFormat:@"[dump/%@][%s] %@", tag ?: @"?", names[i], ts]);
            for (NSString *k in keys) {
                id v = d[k];
                if (v) seFileLog([NSString stringWithFormat:@"[dump] %@ = %@", k, v]);
            }
            NSMutableArray *suspects = [NSMutableArray array];
            for (NSString *k in d) {
                if ([k localizedCaseInsensitiveContainsString:@"daptive"] ||
                    [k localizedCaseInsensitiveContainsString:@"imit"] ||
                    [k localizedCaseInsensitiveContainsString:@"nhibit"] ||
                    [k localizedCaseInsensitiveContainsString:@"nflow"] ||
                    [k localizedCaseInsensitiveContainsString:@"hermal"] ||
                    [k localizedCaseInsensitiveContainsString:@"emperature"] ||
                    [k localizedCaseInsensitiveContainsString:@"hargeInhibit"])
                    [suspects addObject:k];
            }
            if (suspects.count) seFileLog([NSString stringWithFormat:@"[dump] suspect keys: %@", suspects]);
        }
        p_IOObjectRelease(svc);
    }
}

static void seSetSmartCharge(BOOL on) {
    id client = seSmartClient();
    if (!client) {
        seFileLog([NSString stringWithFormat:@"[smart] client create FAILED, cannot set %d", on ? 1 : 0]);
        return;
    }
    int before = seSmartQuery();
    SEL sel = NSSelectorFromString(on ? @"enableSmartCharging:" : @"disableSmartCharging:");
    if (![client respondsToSelector:sel]) {
        seFileLog([NSString stringWithFormat:@"[smart] selector %@ missing", on ? @"enable" : @"disable"]);
        return;
    }
    NSError *err = nil;
    BOOL ok = ((BOOL(*)(id,SEL,NSError**))objc_msgSend)(client, sel, &err);
    int after = seSmartQuery();
    NSString *msg = [NSString stringWithFormat:@"[smart] set %d -> ok=%d before=%d after=%d err=%@",
        on ? 1 : 0, ok, before, after,
        err ? [err localizedDescription] : @"nil"];
    NSLog(@"[SysEnhance] %@", msg);
    seFileLog(msg);   // 状态变化必落盘,装机直接验
}

// v2.6.31: 经 minisfixd(特权 LaunchDaemon)执行写入——SB 进程无 powersource-write
// entitlement(实测 kr=0xE0000001),daemon 持证上岗。协议见 minisfixd.c
static int seDaemonWriteCharging(BOOL on, uint32_t *krA, uint32_t *krI) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(39082);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return -2; }
    unsigned char req[5] = {'M', 'F', 'W', 'R', on ? 1 : 0};
    if (write(fd, req, 5) != 5) { close(fd); return -3; }
    uint32_t out[2] = {0, 0};
    if (read(fd, out, 8) != 8) { close(fd); return -4; }
    close(fd);
    *krA = out[0];
    *krI = out[1];
    return 0;
}

static void seSetCharging(BOOL on) {
    // 主路径: minisfixd 特权写入
    uint32_t krA = 0, krI = 0;
    int rc = seDaemonWriteCharging(on, &krA, &krI);
    NSString *msg;
    if (rc == 0 && (krA == 0 || krI == 0)) {
        msg = [NSString stringWithFormat:@"[set] via daemon on=%d krASB=%u krIOPS=%u",
            on ? 1 : 0, krA, krI];
    } else {
        msg = [NSString stringWithFormat:@"[set] daemon write FAILED rc=%d krASB=%u krIOPS=%u -> fallback direct",
            rc, krA, krI];
        seFileLog(msg);
        // fallback: SB 直写(预期被拒,留作诊断证据)
        if (!seLoadIOKit()) return;
        mach_port_t master = 0;
        p_IOMasterPort(0, &master);
        CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 3,
            &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(d, CFSTR("IsCharging"), kCFBooleanTrue);
        CFDictionarySetValue(d, CFSTR("PredictiveChargingInhibit"),
                             on ? kCFBooleanFalse : kCFBooleanTrue);
        CFDictionarySetValue(d, CFSTR("ExternalConnected"),
                             on ? kCFBooleanTrue : kCFBooleanFalse);
        const char *names[] = {"AppleSmartBattery", "IOPMPowerSource"};
        for (int i = 0; i < 2; i++) {
            se_io_t svc = p_IOServiceGetMatchingService(master, p_IOServiceMatching(names[i]));
            if (!svc) continue;
            kern_return_t kr = p_IORegistryEntrySetCFProperties(svc, d);
            p_IOObjectRelease(svc);
            seFileLog([NSString stringWithFormat:@"[set] direct %s on=%d kr=%d", names[i], on ? 1 : 0, kr]);
        }
        CFRelease(d);
    }
    NSLog(@"[SysEnhance] %@", msg);
    seFileLog(msg);
    // 写后 3s 回读验证——生效与否数据说话
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        seDumpBatteryKeys(on ? @"verify-resume" : @"verify-stop");
    });
}

// v2.6.27: 充电态 IOKit 直读——UIDevice.batteryState 在 SB 里不可靠
// (实测 smart charge inhibit 时报 NotCharging,决策被误导)
static BOOL seReadCharging(void) {
    if (!seLoadIOKit() || !p_IORegistryEntryCreateCFProperties) return NO;
    mach_port_t master = 0;
    p_IOMasterPort(0, &master);
    se_io_t svc = p_IOServiceGetMatchingService(master, p_IOServiceMatching("AppleSmartBattery"));
    if (!svc) svc = p_IOServiceGetMatchingService(master, p_IOServiceMatching("IOPMPowerSource"));
    if (!svc) return NO;
    CFMutableDictionaryRef props = NULL;
    kern_return_t kr = p_IORegistryEntryCreateCFProperties(svc, &props, kCFAllocatorDefault, 0);
    p_IOObjectRelease(svc);
    if (kr != 0 || !props) return NO;
    NSDictionary *d = (__bridge_transfer NSDictionary *)props;
    NSNumber *ext = d[@"ExternalConnected"];
    NSNumber *chg = d[@"IsCharging"];
    // ExternalConnected=插着电; IsCharging=实际在充(inhibit 时为 NO)
    // 决策用「插着电」——inhibit 状态下我们仍要能判断「该不该解除」
    return (ext.boolValue || chg.boolValue);
}

// v2.6.30: 读 AppleSmartBattery 全属性(供断流探测)
static NSDictionary *seReadBatteryDict(void) {
    if (!seLoadIOKit() || !p_IORegistryEntryCreateCFProperties) return @{};
    mach_port_t master = 0;
    p_IOMasterPort(0, &master);
    se_io_t svc = p_IOServiceGetMatchingService(master, p_IOServiceMatching("AppleSmartBattery"));
    if (!svc) svc = p_IOServiceGetMatchingService(master, p_IOServiceMatching("IOPMPowerSource"));
    if (!svc) return @{};
    CFMutableDictionaryRef props = NULL;
    if (p_IORegistryEntryCreateCFProperties(svc, &props, kCFAllocatorDefault, 0) != 0 || !props) {
        p_IOObjectRelease(svc);
        return @{};
    }
    p_IOObjectRelease(svc);
    return [(__bridge_transfer NSDictionary *)props copy];
}

#pragma mark - 充电上限逻辑(5% 回差防抖)

static int seLastCmd = -1; // -1 未定 / 0 已停 / 1 已恢复
static BOOL seSmartRestored = NO; // 系统智能充电是否已还原

static void seApplyCharge(void) {
    @autoreleasepool {
        NSDictionary *p = sePrefs();
        if (![p[@"mfSysChargeEnabled"] boolValue]) {
            // 功能关闭时还原系统智能充电(只做一次,避免反复调用)
            if (!seSmartRestored) { seSetSmartCharge(YES); seSmartRestored = YES; seLastCmd = -1; }
            return;
        }
        seSmartRestored = NO;
        int limit = [p[@"mfSysChargeLimit"] intValue];
        if (limit <= 0) limit = 90;
        if (limit < 50) limit = 50;
        if (limit > 100) limit = 100;

        UIDevice *dev = [UIDevice currentDevice];
        int lvl = (int)(dev.batteryLevel * 100 + 0.5);
        if (lvl <= 0 || lvl > 100) return;
        // v2.6.27: IOKit 直读充电态(ExternalConnected),不信 UIDevice.batteryState
        BOOL charging = seReadCharging();
        static BOOL seDumpedOnce = NO;
        if (!seDumpedOnce) {
            seDumpedOnce = YES;
            seDumpBatteryKeys(@"boot");
            // v2.6.30 决定性实验: 插电但断流(非满电)→主动写恢复充电并回读,
            //   验证 registry 直写在真机上是否有实权
            NSDictionary *bd = seReadBatteryDict();
            BOOL isChg = [bd[@"IsCharging"] boolValue];
            BOOL full = [bd[@"FullyCharged"] boolValue];
            if (charging && !isChg && !full) {
                NSDictionary *bd2 = seReadBatteryDict();
                int tC = [bd2[@"Temperature"] intValue] / 100;
                int amps = [bd2[@"InstantAmperage"] intValue];
                NSString *ts = [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                              dateStyle:NSDateFormatterNoStyle
                                                              timeStyle:NSDateFormatterMediumStyle];
                seFileLog([NSString stringWithFormat:@"[probe %@] plugged-not-charging lvl=%d temp=%d°C mA=%d -> writing resume",
                    ts, lvl, tC, amps]);
                seSetCharging(YES);
            }
        }
        // v2.6.27: 常驻确保系统优化充电关闭(对标 ChargeLimiter 每轮 isSmartChargeEnable 检查)
        //   只在状态为 enable/fullcharge 时才调 disable,避免重复调用副作用
        static int seSmartLast = -9;
        int sq = seSmartQuery();
        if (sq == 1 || sq == 2) { seSetSmartCharge(NO); }
        else if (sq != seSmartLast) {
            // v2.6.33: 状态行带温度——对齐"卡住瞬间"的热状态
            NSDictionary *bd0 = seReadBatteryDict();
            int tempC = [bd0[@"Temperature"] intValue] / 100;
            seFileLog([NSString stringWithFormat:@"[smart] status=%d (no action) lvl=%d temp=%d°C", sq, lvl, tempC]);
        }
        seSmartLast = sq;
        int cmd = -1;
        if (charging && lvl >= limit)           cmd = 0; // 到上限停充
        else if (!charging && lvl <= limit - 5) cmd = 1; // 回差恢复
        // v2.6.18 诊断: 决策变化时打出完整依据(rawLimit 原始值排查滑条落盘)
        static int seLastLoggedCmd = -2;
        if (cmd >= 0 && cmd != seLastLoggedCmd) {
            id raw = p[@"mfSysChargeLimit"];
            NSString *msg = [NSString stringWithFormat:
                @"[%@] charge decision: lvl=%d limit=%d rawLimit=%@ (%s) charging=%d",
                [NSDateFormatter localizedStringFromDate:[NSDate date] dateStyle:NSDateFormatterShortStyle timeStyle:NSDateFormatterMediumStyle],
                lvl, limit, raw ?: @"nil", [raw isKindOfClass:[NSNumber class]] ? "num" : "other",
                charging];
            NSLog(@"[SysEnhance] %@", msg);
            seFileLog(msg);
            seLastLoggedCmd = cmd;
        }
        if (cmd >= 0 && cmd != seLastCmd) {
            seDumpBatteryKeys(cmd == 0 ? @"stop" : @"resume"); // 下发命令前的 registry 快照
            seSetCharging(cmd == 1); // 内部含 3s 后回读验证(verify-*)
            seLastCmd = cmd;
        }
    }
}

#pragma mark - Wi-Fi 永连 hook

static BOOL (*orig_allowIdleSleep)(id, SEL);
static BOOL hook_allowIdleSleep(id self, SEL _cmd) {
    if ([[sePrefs() objectForKey:@"mfSysWifiAlwaysOn"] boolValue]) return NO;
    return orig_allowIdleSleep(self, _cmd);
}

#pragma mark - 自启动(v2.4.0 编入 FolderX.dylib,仅 SpringBoard 注入,无需进程守卫)

void mfSystemEnhanceInit(void);

__attribute__((constructor))
static void SystemEnhanceAutoStart(void) {
    // 按开关自启:全关则零 hook 零监听,改开关后 respring 生效
    NSDictionary *p = sePrefs();
    if ([p[@"mfSysChargeEnabled"] boolValue] || [p[@"mfSysWifiAlwaysOn"] boolValue]) {
        mfSystemEnhanceInit();
    }
}

void mfSystemEnhanceInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 充电监控:通知常驻,回调内实时判开关
        [UIDevice currentDevice].batteryMonitoringEnabled = YES;
        seApplyCharge();
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        void (^blk)(NSNotification *) = ^(NSNotification *n){ seApplyCharge(); };
        [nc addObserverForName:UIDeviceBatteryLevelDidChangeNotification object:nil
                         queue:[NSOperationQueue mainQueue] usingBlock:blk];
        [nc addObserverForName:UIDeviceBatteryStateDidChangeNotification object:nil
                         queue:[NSOperationQueue mainQueue] usingBlock:blk];

        // Wi-Fi 永连:方法替换一次,hook 内实时判开关
        Class sbbc = objc_getClass("SBBacklightController");
        Method m = sbbc ? class_getInstanceMethod(sbbc, @selector(allowIdleSleep)) : NULL;
        if (m && !orig_allowIdleSleep) {
            orig_allowIdleSleep = (BOOL (*)(id, SEL))method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_allowIdleSleep);
        }
        NSLog(@"[SysEnhance] init done (charge monitor + idle-sleep hook)");
    });
}
