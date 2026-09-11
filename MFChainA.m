// MFChainA.m — 链A 探测模块(v2.59.0 第一版: 只探测展示, 不写)
// 架构定位(2026-09-11 定案): SK2 双链设计
//   A 链(通用层): F8 点位数=0 且 SK 形态=SK2 → 启用 — 典型 SK2 app(gongju 型, 单二进制,
//     App Store strip 主二进制符号) 无点位可打; 但权益状态必落 @objc 可见层(PremiumStore 类
//     _TtC 单例 + 实例字段), 我们注入在目标进程内, 运行时枚举可达。
//   B 链(精确层): F8 点位数≥1 → 启用(已有 swifttext 恒真 patch)
// 本版 = 探测: 类枚举 + 权益类识别 + ivar/method dump 上屏。写点(直写字段/建持久规则)下一版。

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <string.h>

// ====== MF 复用接口(extern) ======
extern CGFloat g_mfCardW, g_mfCardH;
extern UIView *mfMakePage(NSString *title, BOOL showBack);
extern void mfPushPage(UIView *page);
extern void mfPopPage(void);
extern void mfToast(NSString *s);
extern void mfLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
@class MFPanelCtrl;   // category 挂点在 MFPanel.m 定义, 此处只声明

#pragma mark - 权益类识别: 名称启发式
// 判定维度: 类名含权益语义。白名单词对齐已实证样本(PremiumStore/PaywallPresenter/
//   AABillStore/ProAccessGuard 家族); 噪声控制: SK/NS/UI 前缀系统类与 SwiftUI 外壳全排除。
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
    // 系统类排除: SK(StoreKit)/NS/UI 前缀; _TtC(带下划线开头的是嵌套类型外壳) 保留判断在词表
    if ([cn hasPrefix:@"SK"] || [cn hasPrefix:@"NS"] || [cn hasPrefix:@"UI"]) return NO;
    for (NSString *p in chainACandidatePats())
        if ([cn rangeOfString:p options:NSCaseInsensitiveSearch].length) return YES;
    return NO;
}

#pragma mark - 枚举(安全模式: 对标 mfProbeStoreKit2 v2.52.3 — 原子快照 + strdup 自持)
// 事故链教训(勿重蹈): 逐索引 _dyld_get_image_name 在动态 dlopen app 上踩悬挂指针(Real Crash #2);
//   objc_copyClassList 全进程 realize 触发 Swift 泛型 conformance 空指针(Real Crash #1)。
//   → 只用 objc_copyClassNamesForImage(懒 realize, 只取名字) + objc_getClass(单点)。
static NSMutableArray *g_chainARows = nil;   // [{name, img, ivars, methods}]
static NSObject *g_chainALock = nil;
static BOOL g_chainAScanned = NO;

static NSDictionary *chainADumpClass(const char *cname, NSString *imgLeaf) {
    Class c = objc_getClass(cname);
    if (!c) return nil;
    // ivar 枚举: PremiumStore 型单例字段(isPremium/unlocked/paid…)都在这
    unsigned ivc = 0;
    Ivar *ivs = class_copyIvarList(c, &ivc);
    NSMutableArray *ivars = [NSMutableArray array];
    for (unsigned k = 0; k < ivc; k++) {
        const char *in = ivar_getName(ivs[k]);
        const char *ty = ivar_getTypeEncoding(ivs[k]);
        if (!in) continue;
        [ivars addObject:[NSString stringWithFormat:@"%s%s%@",
            (ty && !strcmp(ty, "B")) ? "bool " : "", in,
            (ty && !strcmp(ty, "B")) ? @"" : [NSString stringWithFormat:@" (%s)", ty ?: "?"]]];
    }
    if (ivs) free(ivs);
    // method 枚举: @objc 可见的 getter(纯 Swift computed property 不进 method list — 探测版如实展示)
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
    // bool 字段探测计数(A 链直写的候选目标)
    unsigned boolCnt = 0;
    for (NSString *iv in ivars)
        if ([iv hasPrefix:@"bool "]) boolCnt++;
    return @{
        @"name": [NSString stringWithUTF8String:cname],
        @"img": imgLeaf,
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
            if (!im || !strstr(im, ".app/")) continue;   // 只扫 app 自有镜像, 系统 cache 全排除
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
                NSDictionary *d = chainADumpClass(names[j], leaf);
                if (d) { [g_chainARows addObject:d]; clsFound++; }
            }
            free(names);
        }
        for (unsigned i = 0; i < nSafe; i++) free(safe[i]);
        free(safe);
        mfLog(@"[chainA] 探测: %u 个权益类(bool 字段候选见详情)", clsFound);
    }
}

// F8/侦查分流判据的对外只读接口
unsigned long mfChainAClassCount(void) {
    @synchronized (g_chainALock ?: (g_chainALock = [NSObject new])) {
        return g_chainARows.count;
    }
}

#pragma mark - A 链探测列表页(UITableView, 对标 MFAPEntList)
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
    st.text = bools ? [NSString stringWithFormat:@"bool 字段 %u 个 — A 链直写候选", bools] : @"无 bool ivar(纯 Swift 判定, 待 B 链/fixup)";
    st.textColor = bools ? [UIColor systemGreenColor] : [UIColor tertiaryLabelColor];
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    // 点行 → 详情: ivar/method 全量 dump(可长按复制文本由 UITextView 自带)
    NSDictionary *d = self.rows[ip.row];
    UIView *page = mfMakePage([NSString stringWithFormat:@"A链 · %@", d[@"name"]], YES);
    NSMutableString *txt = [NSMutableString string];
    [txt appendFormat:@"类: %@\n镜像: %@\n\n== ivars ==\n", d[@"name"], d[@"img"]];
    for (NSString *iv in (NSArray *)d[@"ivars"]) [txt appendFormat:@"  %@\n", iv];
    [txt appendString:@"\n== methods(@objc 可见) ==\n"];
    for (NSString *m in (NSArray *)d[@"methods"]) [txt appendFormat:@"  %@\n", m];
    UITextView *tv2 = [[UITextView alloc] initWithFrame:CGRectMake(12, 54, g_mfCardW - 24, g_mfCardH - 66)];
    tv2.text = txt;
    tv2.font = [UIFont fontWithName:@"Menlo" size:11];
    tv2.editable = NO;
    tv2.selectable = YES;
    tv2.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    tv2.layer.cornerRadius = 10;
    [page addSubview:tv2];
    mfPushPage(page);
}
@end
static MFChainAList *g_chainAList = nil;

@implementation MFPanelCtrl (ChainA)
// A 链探测入口: 实验模拟页按钮 → 扫描 + 列表
- (void)mfChainAShowPage {
    chainAScan();
    if (!g_chainARows.count) {
        mfToast(@"无权益类候选(类名无 Premium/Paywall/Entitle 语义)");
        mfLog(@"[chainA] 探测: 0 命中 — 非典型型, 考虑 fixup 重绑(开发中)");
        return;
    }
    UIView *page = mfMakePage(@"🅰️ A链 · 权益类探测", YES);
    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 32, 34)];
    hint.text = @"点位 0 的 SK2 型走此链 — 点行看 ivar/method, bool 字段 = 直写候选";
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
