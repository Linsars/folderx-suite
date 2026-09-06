// ====== MFBatteryInfo.m — 电池详情页 (v2.6.21) ======
// 对标 ChargeLimiter (lich4) 的电池/电源信息面板:
//   IORegistryEntryCreateCFProperties 直读 AppleSmartBattery( iPhone8+ ) /
//   IOPMPowerSource 兜底, 全量属性展示。
// 只读不写, app 进程可安全调用; 5s 自动刷新, 页面 pop 自动停表。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "MFPanel.h"
#import <IOKit/IOMessage.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dlfcn.h>

// dlsym 零链接依赖 IOKit
typedef mach_port_t bi_io_t;
static mach_port_t (*bi_IOMasterPort)(mach_port_t, mach_port_t *);
static CFMutableDictionaryRef (*bi_IOServiceMatching)(const char *);
static bi_io_t (*bi_IOServiceGetMatchingService)(mach_port_t, CFMutableDictionaryRef);
static kern_return_t (*bi_IORegistryEntryCreateCFProperties)(bi_io_t, CFMutableDictionaryRef *, CFAllocatorRef, UInt32);
static kern_return_t (*bi_IOObjectRelease)(bi_io_t);

static BOOL biLoadIOKit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlsym(RTLD_DEFAULT, "IOMasterPort");
        if (!h) h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        if (!h) return;
        bi_IOMasterPort = dlsym(RTLD_DEFAULT, "IOMasterPort");
        bi_IOServiceMatching = dlsym(RTLD_DEFAULT, "IOServiceMatching");
        bi_IOServiceGetMatchingService = dlsym(RTLD_DEFAULT, "IOServiceGetMatchingService");
        bi_IORegistryEntryCreateCFProperties = dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperties");
        bi_IOObjectRelease = dlsym(RTLD_DEFAULT, "IOObjectRelease");
    });
    return bi_IOMasterPort != NULL;
}

// 经 SpringBoard(FolderX 注入)的 loopback TCP 查询——app 沙盒 mach-lookup deny
// CFMessagePort 不可达, 127.0.0.1 TCP 不过那道门(ChargeLimiter 同款思路)
static NSDictionary *biViaSpringBoard(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return nil;
    struct timeval tv = {2, 0}; // 收发超时 2s
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(39081);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        NSLog(@"[MF-Bat] connect 127.0.0.1:39081 refused (SB not listening?)");
        return nil;
    }
    if (write(fd, "MFBA", 4) != 4) { close(fd); return nil; }
    uint32_t nlen = 0;
    if (read(fd, &nlen, 4) != 4) { close(fd); return nil; }
    uint32_t len = ntohl(nlen);
    if (len == 0 || len > 1048576) { close(fd); return nil; }
    NSMutableData *buf = [NSMutableData dataWithLength:len];
    uint8_t *p = buf.mutableBytes;
    ssize_t got = 0;
    while (got < (ssize_t)len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n <= 0) break;
        got += n;
    }
    close(fd);
    NSDictionary *out = [NSPropertyListSerialization propertyListWithData:buf options:0 format:NULL error:NULL];
    NSLog(@"[MF-Bat] via TCP ok: %lu keys, %u bytes", (unsigned long)out.count, len);
    return out;
}

NSDictionary *mfBatteryRead(void) {
    if (!biLoadIOKit()) {
        NSLog(@"[MF-Bat] IOKit dlsym failed -> SB relay");
        return biViaSpringBoard();
    }
    mach_port_t master = 0;
    bi_IOMasterPort(0, &master);
    bi_io_t svc = bi_IOServiceGetMatchingService(master, bi_IOServiceMatching("AppleSmartBattery"));
    if (!svc) svc = bi_IOServiceGetMatchingService(master, bi_IOServiceMatching("IOPMPowerSource"));
    if (svc) {
        CFMutableDictionaryRef props = NULL;
        kern_return_t kr = bi_IORegistryEntryCreateCFProperties(svc, &props, kCFAllocatorDefault, 0);
        bi_IOObjectRelease(svc);
        // v2.6.23: 沙盒 app 常见 kr=0 但属性被裁剪 → 也走 SB 中转
        if (kr == 0 && props) {
            NSDictionary *d = [(__bridge_transfer NSDictionary *)props copy];
            NSLog(@"[MF-Bat] direct read kr=0 keys=%lu", (unsigned long)d.count);
            if (d.count > 4) return d; // 少于5键视为沙盒裁剪
            NSLog(@"[MF-Bat] sandbox-trimmed (<5 keys) -> SB relay");
        } else {
            NSLog(@"[MF-Bat] direct read failed kr=%d -> SB relay", kr);
        }
    } else {
        NSLog(@"[MF-Bat] service lookup =0 -> SB relay");
    }
    return biViaSpringBoard();
}

#pragma mark - 固定字段清单(v2.6.21 用户指定 16 项)

static NSString *biFmtVal(NSString *key, id v) {
    if (v == nil || v == [NSNull null]) return @"—";
    if ([key isEqualToString:@"Temperature"]) {
        NSNumber *n = [v isKindOfClass:[NSNumber class]] ? v : nil;
        return n ? [NSString stringWithFormat:@"%.1f °C", n.doubleValue / 100.0] : [v description];
    }
    if ([key isEqualToString:@"BootVoltage"] || [key isEqualToString:@"Voltage"] || [key isEqualToString:@"AdpVoltage"]) {
        NSNumber *n = [v isKindOfClass:[NSNumber class]] ? v : nil;
        return n ? [NSString stringWithFormat:@"%.3f V", n.doubleValue / 1000.0] : [v description]; // mV → V
    }
    if ([v isKindOfClass:[NSNumber class]]) return [v stringValue];
    return [v description] ?: @"—";
}

// 充电状态: 慢充/快充/无线/未充电
// 判定: IsWireless→无线; 功率>=18W 或适配器电压>=9V(PD)→快充; 其余→慢充
static NSString *biChargeMode(NSDictionary *d) {
    NSDictionary *adp = [d[@"AdapterDetails"] isKindOfClass:[NSDictionary class]] ? d[@"AdapterDetails"] : nil;
    BOOL plugged = [d[@"ExternalConnected"] boolValue];
    BOOL charging = [d[@"IsCharging"] boolValue];
    if (!plugged && !charging) return @"未充电";
    if (adp) {
        BOOL wireless = [adp[@"IsWireless"] boolValue] ||
            [[(NSString *)adp[@"Description"] lowercaseString] containsString:@"wireless"];
        NSNumber *watts = [adp[@"Watts"] isKindOfClass:[NSNumber class]] ? adp[@"Watts"] : nil;
        NSNumber *volts = [adp[@"AdapterVoltage"] isKindOfClass:[NSNumber class]] ? adp[@"AdapterVoltage"]
                        : ([adp[@"Voltage"] isKindOfClass:[NSNumber class]] ? adp[@"Voltage"] : nil);
        if (wireless) return @"无线充电";
        if ((watts && watts.doubleValue >= 18) || (volts && volts.doubleValue >= 9000)) return @"快充";
        return @"慢充";
    }
    return charging ? @"充电中" : @"已接电源";
}

// 行定义: 标题 | 来源键 | 是否需要换算
static NSArray *biBuildRows(void) {
    NSDictionary *d = mfBatteryRead();
    if (!d.count) return @[ @{@"t": @"读取失败", @"v": @"IOKit 不可用"} ];
    NSNumber *design = [d[@"DesignCapacity"] isKindOfClass:[NSNumber class]] ? d[@"DesignCapacity"] : nil;
    NSNumber *nominal = [d[@"NominalChargeCapacity"] isKindOfClass:[NSNumber class]] ? d[@"NominalChargeCapacity"] : nil;

    // 健康度 = 标称满容量/设计容量
    NSString *health = @"—";
    if (design && nominal && design.doubleValue > 0)
        health = [NSString stringWithFormat:@"%.1f%%", nominal.doubleValue / design.doubleValue * 100];

    NSMutableArray<NSDictionary *> *rows = [NSMutableArray array];
    void (^row)(NSString *, NSString *) = ^(NSString *t, NSString *v) { [rows addObject:@{@"t": t, @"v": v ?: @"—"}]; };
    row(@"健康度", health);
    row(@"电池温度", biFmtVal(@"Temperature", d[@"Temperature"]));
    row(@"电池状态", biChargeMode(d));
    row(@"充电次数", biFmtVal(@"CycleCount", d[@"CycleCount"]));
    row(@"设计容量 (mAh)", biFmtVal(@"DesignCapacity", design));
    row(@"实际容量 (mAh)", biFmtVal(@"NominalChargeCapacity", nominal));
    row(@"当前电量 (mAh)", biFmtVal(@"AppleRawCurrentCapacity", d[@"AppleRawCurrentCapacity"]));
    // v2.6.34: 对齐 ChargeLimiter 口径(app.js L589)——raw库仑计/标称容量,精确反映实际储能
    //   旧值 CurrentCapacity 是系统UI量化值(整数+保守校准),与真实储能可差 2%+
    {
        NSNumber *rawCap = [d[@"AppleRawCurrentCapacity"] isKindOfClass:[NSNumber class]] ? d[@"AppleRawCurrentCapacity"] : nil;
        NSNumber *nomCap = [d[@"NominalChargeCapacity"] isKindOfClass:[NSNumber class]] ? d[@"NominalChargeCapacity"] : nil;
        if (!nomCap) nomCap = [d[@"AppleRawMaxCapacity"] isKindOfClass:[NSNumber class]] ? d[@"AppleRawMaxCapacity"] : nil; // CL 同款兜底
        if (rawCap && nomCap && nomCap.doubleValue > 0)
            row(@"硬件电量 (%)", [NSString stringWithFormat:@"%.2f%%", rawCap.doubleValue / nomCap.doubleValue * 100]);
        else
            row(@"硬件电量 (%)", biFmtVal(@"CurrentCapacity", d[@"CurrentCapacity"])); // 兜底回退
    }
    row(@"电池电流 (mA)", biFmtVal(@"Amperage", d[@"Amperage"]));
    row(@"瞬时电流 (mA)", biFmtVal(@"InstantAmperage", d[@"InstantAmperage"]));
    row(@"开机电压", biFmtVal(@"BootVoltage", d[@"BootVoltage"]));
    row(@"电池电压", biFmtVal(@"Voltage", d[@"Voltage"]));
    row(@"序列号", biFmtVal(@"Serial", d[@"Serial"]));
    NSDictionary *adp = [d[@"AdapterDetails"] isKindOfClass:[NSDictionary class]] ? d[@"AdapterDetails"] : nil;
    row(@"电源电压", biFmtVal(@"AdpVoltage", adp[@"Voltage"] ?: adp[@"AdapterVoltage"]));
    row(@"电源电流 (mA)", biFmtVal(nil, adp[@"Current"]));
    row(@"电源功率 (W)", biFmtVal(nil, adp[@"Watts"]));
    return rows;
}

#pragma mark - 详情页

void mfShowBatteryPage(void);

// 列表模型: 平铺的 (标题, 值) 行
@interface MFBatteryList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *rows; // @{t:, v:}
@end
@implementation MFBatteryList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return self.rows.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *idt = @"mfBatRow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:idt];
    if (!c) {
        c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:idt];
        c.backgroundColor = UIColor.clearColor;
        c.textLabel.font = [UIFont systemFontOfSize:12];
        c.textLabel.textColor = [UIColor secondaryLabelColor];
        c.detailTextLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        c.detailTextLabel.textColor = [UIColor labelColor];
        c.selectionStyle = UITableViewCellSelectionStyleNone;
    }
    NSDictionary *r = self.rows[ip.row];
    c.textLabel.text = r[@"t"];
    c.detailTextLabel.text = r[@"v"];
    return c;
}
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSDictionary *r = self.rows[ip.row];
    UIContextualAction *copy = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"复制" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [UIPasteboard generalPasteboard].string =
                [NSString stringWithFormat:@"%@ = %@", r[@"t"], r[@"v"]];
            done(YES);
        }];
    copy.backgroundColor = [UIColor systemBlueColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[copy]];
}
@end


void mfShowBatteryPage(void) {
    UIView *page = mfMakePage(@"电池详情", YES);

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(16, 44, g_mfCardW - 32, 18)];
    status.tag = 301;
    status.font = [UIFont systemFontOfSize:11];
    status.textColor = [UIColor tertiaryLabelColor];
    status.text = @"5 秒自动刷新 · 左划复制";
    [page addSubview:status];

    UITableView *tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 64, g_mfCardW, g_mfCardH - 64) style:UITableViewStylePlain];
    tv.tag = 310;
    tv.backgroundColor = [UIColor tertiarySystemBackgroundColor];
    tv.separatorColor = [UIColor separatorColor];
    MFBatteryList *list = [MFBatteryList new];
    list.rows = biBuildRows();
    tv.dataSource = list;
    tv.delegate = list;
    objc_setAssociatedObject(page, "batList", list, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [page addSubview:tv];

    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 5.0 * NSEC_PER_SEC, 0.5 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        if (!page.superview) { dispatch_source_cancel(timer); return; }
        UITableView *ltv = [page viewWithTag:310];
        MFBatteryList *ll = objc_getAssociatedObject(page, "batList");
        if (!ltv || !ll) return;
        ll.rows = biBuildRows();
        [ltv reloadData];
    });
    dispatch_resume(timer);
    objc_setAssociatedObject(page, "batTimer", timer, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    mfPushPage(page);
}
