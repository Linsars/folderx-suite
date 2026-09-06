// ====== MFObjCHook.m - 精确 ObjC 方法 hook(返回值改写) ======
// 取代只读的 MFMethodTrace(方法监控)。引擎提炼自原 MFMethodTrace 的 block-IMP 包装,
//   改为「返回值改写」模式: 对当前 app(class+selector)短路/替换返回值。
//   作用域: 仅当前面板所在 app(规则管理同款范式, 避免全局干扰其他进程)。
// 配置持久化: /var/jb/Library/MinisFix/objchooks.plist
//   规则: [{class, selector, mode, value, enabled}]  mode: 0=orig 1=nil 2=str(value)
#import "MFPanel.h"
#import <objc/runtime.h>

// v2.6.50: /var/jb/Library/MinisFix/ 在 rootless 下不可写(实测 save fail)
//   改用用户空间路径(与网络规则/电池日志同层)
static NSString *MF_OBJC_HOOK_PATH = @"/var/jb/var/mobile/Library/MinisFix/objchooks.plist";
static NSString *g_objcPrefill = nil;
static void mfObjCHookLoad(void);  // 前向声明
// v2.6.44: 全程诊断日志(NSLog 双写进 hostlog 管道)
#define OH_LOG(fmt, ...) NSLog(@"[ObCHook] " fmt, ##__VA_ARGS__)
// v2.6.41: 实现 mfTraceSetPrefill(MFPanel.h 声明 + MFClassDump.m 调用, 之前漏实现 = undefined symbol)
void mfTraceSetPrefill(NSString *cls) {
    g_objcPrefill = cls ? [cls copy] : nil;
}
static NSMutableArray *g_objcHooks = nil;      // 规则(dict)
static NSMutableArray *g_hookRestore = nil;    // 已应用 {cls,sel,origIMP,enc}
static BOOL g_hookOn = NO;
static NSInteger g_editIdx = -1;               // v2.6.79: 点 cell 编辑时载入的规则索引(-1=新规则)
static UITextField *g_clsF = nil, *g_selF = nil, *g_valF = nil;   // v2.6.47 表单字段
static UISegmentedControl *g_modeSeg = nil;
static BOOL g_applySilent = NO;   // v2.6.57 ctor 静默标志

#pragma mark - 安全签名解析(NSMethodSignature)
// 只接受 ret=@/v + 参数全 @(≤4)。返回对象/void 方法可接管, 其余跳过。
static int mfSafeArgs(const char *t, char *retOut) {
    if (!t) return -1;
    @try {
        NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes:t];
        if (!sig) return -1;
        char ret = [sig getArgumentTypeAtIndex:0][0];
        // v2.6.55: 支持 q(long long)/i(int)/c(BOOL) 返回——SK getter 多用
        if (ret != '@' && ret != 'v' && ret != 'q' && ret != 'i' && ret != 'c') return -1;
        // v2.6.46: 无参方法 sig.numberOfArguments=2(self+_cmd), 2-3 下溢→全被拒
        NSUInteger n = sig.numberOfArguments > 2 ? sig.numberOfArguments - 3 : 0;
        if (n > 4) return -1;
        for (NSUInteger i = 3; i < sig.numberOfArguments; i++) {
            const char *ty = [sig getArgumentTypeAtIndex:i];
            if (ty[0] != '@') return -1;
        }
        *retOut = ret;
        return (int)n;
    } @catch (NSException *e) { return -1; }
}

#pragma mark - 返回值改写 wrapper
static IMP mfWrapRet(char ret, int nargs, IMP orig, int mode, id val) {
    IMP o = orig; int rm = mode; id rv = val;
    id blk = nil;
    if (ret == 'v') {
        if (nargs == 0) { blk = ^void(id s, SEL c){ ((void(*)(id,SEL))o)(s,c); }; }
        else if (nargs == 1) { blk = ^void(id s, SEL c, id a1){ ((void(*)(id,SEL,id))o)(s,c,a1); }; }
        else if (nargs == 2) { blk = ^void(id s, SEL c, id a1, id a2){ ((void(*)(id,SEL,id,id))o)(s,c,a1,a2); }; }
        else if (nargs == 3) { blk = ^void(id s, SEL c, id a1, id a2, id a3){ ((void(*)(id,SEL,id,id,id))o)(s,c,a1,a2,a3); }; }
        else { blk = ^void(id s, SEL c, id a1, id a2, id a3, id a4){ ((void(*)(id,SEL,id,id,id,id))o)(s,c,a1,a2,a3,a4); }; }
    } else { // '@'
        if (nargs == 0) { blk = ^id(id s, SEL c){ if(rm==0)return ((id(*)(id,SEL))o)(s,c); if(rm==1)return nil; return rv; }; }
        else if (nargs == 1) { blk = ^id(id s, SEL c, id a1){ if(rm==0)return ((id(*)(id,SEL,id))o)(s,c,a1); if(rm==1)return nil; return rv; }; }
        else if (nargs == 2) { blk = ^id(id s, SEL c, id a1, id a2){ if(rm==0)return ((id(*)(id,SEL,id,id))o)(s,c,a1,a2); if(rm==1)return nil; return rv; }; }
        else if (nargs == 3) { blk = ^id(id s, SEL c, id a1, id a2, id a3){ if(rm==0)return ((id(*)(id,SEL,id,id,id))o)(s,c,a1,a2,a3); if(rm==1)return nil; return rv; }; }
        else { blk = ^id(id s, SEL c, id a1, id a2, id a3, id a4){ if(rm==0)return ((id(*)(id,SEL,id,id,id,id))o)(s,c,a1,a2,a3,a4); if(rm==1)return nil; return rv; }; }
    }
    // v2.6.55: 数字返回(mode=3→1) — 只支持 nargs=0(transactionState 等)
    if ((ret == 'q' || ret == 'i' || ret == 'c') && nargs == 0) {
        if (ret == 'q') blk = ^long long(id s, SEL c){ return 1LL; };
        else if (ret == 'i') blk = ^int(id s, SEL c){ return 1; };
        else blk = ^BOOL(id s, SEL c){ return YES; };
    }
    // v2.6.77: Swift Bool ('B') 支持——PurchasesReceiptParser.receiptHasTransactionsWithReceiptData: 返回 _Bool
    if ((ret == 'B' || ret == 'b') && nargs == 1 && mode == 4) {
        blk = ^BOOL(id s, SEL c, id a1){ return YES; };
    } else if ((ret == 'B' || ret == 'b') && nargs == 1) {
        BOOL (*orB)(id,SEL,id) = (void *)orig;
        blk = ^BOOL(id s, SEL c, id a1){ return orB(s, c, a1); };
    }
    return blk ? imp_implementationWithBlock(blk) : nil;
}

// v2.6.75 观察模式：mode=3 → 调原方法 + 完整打日志（找出判定读取的 key/参数），不改行为
// v2.6.76 修正：只记录 value 前缀匹配的 key（value 域=前缀），日志节流；本函数不 hook NSUserDefaults(见 apply 防护)
static IMP mfObjCWrapObserve(Method m, NSString *cls, NSString *sel, NSString *prefix) {
    IMP orig = method_getImplementation(m);
    NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes:method_getTypeEncoding(m)];
    NSUInteger nargs = sig.numberOfArguments;
    char ret = sig.methodReturnType[0];
    if (orig) {
#define MFOBS_LOG2(KEY...) do { OH_LOG(@"OBS[%@ %@] %@", cls, sel, [NSString stringWithFormat:KEY]); } while(0)
        if (ret == '@' && nargs == 3) {
            id (*or3)(id,SEL,id) = (void *)orig;
            return imp_implementationWithBlock(^id(id s, SEL c, id a0){
                if (a0 && (!prefix.length || [a0 hasPrefix:prefix])) {
                    MFOBS_LOG2(@"a0=%@", a0);
                    return or3(s, c, a0);
                }
                return or3(s, c, a0);
            });
        } else if (ret == '@' && nargs == 2) {
            id (*or2)(id,SEL) = (void *)orig;
            return imp_implementationWithBlock(^id(id s, SEL c){
                MFOBS_LOG2(@"(no-arg)");
                return or2(s, c);
            });
        } else if ((ret == 'c' || ret == 'B') && nargs == 3) {
            BOOL (*orB)(id,SEL,id) = (void *)orig;
            return imp_implementationWithBlock(^BOOL(id s, SEL c, id a0){
                BOOL v = orB(s, c, a0);
                if (a0 && (!prefix.length || [a0 hasPrefix:prefix])) MFOBS_LOG2(@"a0=%@ -> %d", a0, v);
                return v;
            });
        } else if ((ret == 'q' && nargs == 3)) {
            long long (*orQ3)(id,SEL,id) = (void *)orig;
            return imp_implementationWithBlock(^long long(id s, SEL c, id a0){
                long long v = orQ3(s, c, a0);
                if (a0 && (!prefix.length || [a0 hasPrefix:prefix])) MFOBS_LOG2(@"a0=%@ -> %lld", a0, v);
                return v;
            });
        }
    }
    return NULL;
}

#pragma mark - 应用/还原
// ctor 静默应用包装(不弹 toast)
void mfObjCHookApplySilent(void) {
    g_applySilent = YES;
    mfObjCHookApply();
    g_applySilent = NO;
}

// v2.6.57: 全还原→再应用(幂等, restore 表不被污染) + hooked 计数 + silent(ctor 静默)
void mfObjCHookApply(void) {
    if (!g_objcHooks) mfObjCHookLoad();
    if (!g_hookRestore) g_hookRestore = [NSMutableArray new];
    // 先还原所有已应用的(取回真 orig)
    for (NSDictionary *e in g_hookRestore) {
        Class c = e[@"cls"]; SEL sel = NSSelectorFromString(e[@"sel"]);
        IMP orig = (IMP)[e[@"imp"] pointerValue];
        const char *enc = [e[@"enc"] UTF8String];
        Method old = class_getInstanceMethod(c, sel);
        if (old && method_getImplementation(old) != orig) class_replaceMethod(c, sel, orig, enc);
    }
    [g_hookRestore removeAllObjects];
    // 再按规则应用
    int hooked = 0;
    for (NSDictionary *rule in g_objcHooks) {
        if (![rule[@"enabled"] boolValue]) continue;
        Class cls = NSClassFromString(rule[@"class"]);
        if (!cls) { OH_LOG(@"skip: class %@ not found", rule[@"class"]); continue; }
        SEL sel = NSSelectorFromString(rule[@"selector"]);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) { OH_LOG(@"skip: selector %@ not found on %@", rule[@"selector"], rule[@"class"]); continue; }
        const char *enc = method_getTypeEncoding(m);
        char ret; int args = mfSafeArgs(enc, &ret);
        if (args < 0) { OH_LOG(@"skip: unsafe signature %@#%@", rule[@"class"], rule[@"selector"]); continue; }
        // v2.6.76 防护：NSUserDefaults 读方法在 UIKit/UIFoundation +initialize 期被高频调用，
        // hook 它们会触发初始化链死锁 → 启动看门狗 SIGKILL(实测 140407.ips)。观察改为用 Defaults 浏览器(纯读取)。
        NSString *clsN = rule[@"class"], *selN = rule[@"selector"];
        if ([clsN isEqualToString:@"NSUserDefaults"] &&
            ([selN hasPrefix:@"objectForKey"] || [selN hasPrefix:@"boolForKey"] || [selN hasPrefix:@"stringForKey"] || [selN hasPrefix:@"integerForKey"] || [selN hasPrefix:@"valueForKey"])) {
            OH_LOG(@"skip(guard): NSUserDefaults 读方法禁止 hook -> 用 Defaults 浏览器看 key %@#%@", clsN, selN);
            continue;
        }
        IMP orig = method_getImplementation(m);
        int ruleMode = [rule[@"mode"] intValue];
        IMP wrap = NULL;
        if (ruleMode == 3) {
            // v2.6.78 观察模式独立旁路：绝不强制，纯透传+日志（避免 'B' 分支误伤）
            wrap = mfObjCWrapObserve(m, rule[@"class"], rule[@"selector"], rule[@"value"]);
        } else {
            wrap = mfWrapRet(ret, args, orig, ruleMode, rule[@"value"]);
        }
        if (!wrap) { OH_LOG(@"skip: wrap fail %@#%@", rule[@"class"], rule[@"selector"]); continue; }
        if (class_getMethodImplementation(cls, sel) != orig) class_addMethod(cls, sel, wrap, enc);
        else method_setImplementation(m, wrap);
        [g_hookRestore addObject:@{@"cls": cls, @"sel": NSStringFromSelector(sel), @"imp": [NSValue valueWithPointer:orig], @"enc": [NSString stringWithUTF8String:enc]}];
        hooked++;
        OH_LOG(@"hook OK: %@#%@ mode=%d", rule[@"class"], rule[@"selector"], ruleMode);
    }
    g_hookOn = hooked > 0;
    if (hooked > 0 && !g_applySilent) mfToast([NSString stringWithFormat:@"🔧 ObjC 规则已应用 (%d条)", hooked]);
    else if (!g_applySilent && hooked == 0) OH_LOG(@"apply: no hook applied (silent)");
}

void mfObjCHookStop(void) {
    if (!g_hookRestore) return;
    for (NSDictionary *e in g_hookRestore) {
        Class c = e[@"cls"]; SEL sel = NSSelectorFromString(e[@"sel"]);
        IMP orig = (IMP)[e[@"imp"] pointerValue];
        const char *enc = [e[@"enc"] UTF8String];
        Method old = class_getInstanceMethod(c, sel);
        if (old && method_getImplementation(old) == orig) continue;
        class_replaceMethod(c, sel, orig, enc);
    }
    [g_hookRestore removeAllObjects];
    g_hookOn = NO;
    mfToast(@"⏹️ ObjC 规则已停止");
}

#pragma mark - 持久化
void mfObjCHookLoad(void) {
    NSArray *a = [NSArray arrayWithContentsOfFile:MF_OBJC_HOOK_PATH];
    g_objcHooks = a ? [a mutableCopy] : [NSMutableArray new];
    OH_LOG(@"load: %lu rules from %@", (unsigned long)g_objcHooks.count, MF_OBJC_HOOK_PATH);
}
void mfObjCHookSave(void) {
    // v2.6.49: 先建目录——writeToFile 遇不存在目录静默失败(14:05 rules=0 实锤)
    NSString *dir = [MF_OBJC_HOOK_PATH stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    BOOL ok = [g_objcHooks writeToFile:MF_OBJC_HOOK_PATH atomically:YES];
    OH_LOG(@"save: %lu rules -> %d", (unsigned long)g_objcHooks.count, ok);
}

#pragma mark - UI
void mfShowObjCHookPage(void) {
    if (!g_objcHooks) mfObjCHookLoad();
    // v2.6.45: 防重入——重复点击不叠加页面(v2.6.44 日志暴露 page open 循环)
    if ([[(UIView *)g_mfPages.lastObject accessibilityIdentifier] isEqualToString:@"mf_objcrules"]) return;
    OH_LOG(@"page open: rules=%lu prefill=%@", (unsigned long)g_objcHooks.count, g_objcPrefill);
    UIView *page = mfMakePage(@"🔧 ObjC 规则", YES);
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 48, g_mfCardW, g_mfCardH - 48)];
    [page addSubview:sv];
    CGFloat cw = g_mfCardW;
    CGFloat y = 8;

    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, y, cw-32, 20)];
    hint.text = @"精确 hook 方法返回值(作用于当前 app)";
    hint.font = [UIFont systemFontOfSize:11]; hint.textColor = [UIColor tertiaryLabelColor];
    hint.numberOfLines = 0; [sv addSubview:hint]; y += 24;

    // v2.6.47: 页面内表单(替代系统弹窗)——对齐面板原生交互
    g_clsF = [[UITextField alloc] initWithFrame:CGRectMake(16, y, (cw-40)/2, 34)];
    g_clsF.placeholder = @"类名 (NSBundle)";
    [sv addSubview:g_clsF];
    g_selF = [[UITextField alloc] initWithFrame:CGRectMake(24+(cw-40)/2, y, (cw-40)/2, 34)];
    g_selF.placeholder = @"方法 (appStoreReceiptURL)";
    [sv addSubview:g_selF]; y += 40;
    g_modeSeg = [[UISegmentedControl alloc] initWithItems:@[@"透传", @"返回 nil", @"str 值", @"观察", @"✔YES"]];
    g_modeSeg.frame = CGRectMake(16, y, cw - 32, 30);   // v2.7.1: 全宽一行，5 项不再截断
    g_modeSeg.selectedSegmentIndex = 1;
    [sv addSubview:g_modeSeg]; y += 38;
    g_valF = [[UITextField alloc] initWithFrame:CGRectMake(16, y, cw - 32, 34)];
    g_valF.placeholder = @"str 值(str 模式用)";
    [sv addSubview:g_valF]; y += 42;
    for (UITextField *f in @[g_clsF, g_selF, g_valF]) {
        f.font = [UIFont systemFontOfSize:12];
        f.borderStyle = UITextBorderStyleRoundedRect;
        f.autocapitalizationType = UITextAutocapitalizationTypeNone;
        f.autocorrectionType = UITextAutocorrectionTypeNo;
        mfAttachKbBar(f);   // v2.7.1: 键盘收起工具条
    }
    if (g_objcPrefill) { g_clsF.text = g_objcPrefill; g_objcPrefill = nil; }
    UIButton *addBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    addBtn.frame = CGRectMake(16, y, cw-32, 38);
    addBtn.backgroundColor = [UIColor systemIndigoColor]; addBtn.layer.cornerRadius = 9;
    addBtn.tintColor = UIColor.whiteColor; [addBtn setTitle:@"➕ 添加" forState:UIControlStateNormal];
    [addBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCHookFormAddTapped") forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:addBtn]; y += 46;

    // v2.6.71: 方法定位器——输入 selector 扫全类找宿主(混淆 app 判定方法的归属类)
    UIButton *locBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    locBtn.frame = CGRectMake(16, y, cw-32, 38);
    locBtn.backgroundColor = [UIColor systemTealColor]; locBtn.layer.cornerRadius = 9;
    locBtn.tintColor = UIColor.whiteColor;
    [locBtn setTitle:@"🎯 定位方法(找类名)" forState:UIControlStateNormal];
    [locBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCLocatorTapped") forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:locBtn]; y += 46;

    // v2.6.76: Defaults 浏览器——纯读取当前 app defaults 全 key（观察判定字段的安全替代，零 hook）
    UIButton *dbrBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    dbrBtn.frame = CGRectMake(16, y, cw-32, 38);
    dbrBtn.backgroundColor = [UIColor systemIndigoColor]; dbrBtn.layer.cornerRadius = 9;
    dbrBtn.tintColor = UIColor.whiteColor;
    [dbrBtn setTitle:@"🔍 Defaults 浏览器(纯读取)" forState:UIControlStateNormal];
    [dbrBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDefaultsBrowserTapped") forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:dbrBtn]; y += 46;

    for (NSDictionary *r in g_objcHooks) {
        UIView *row = [[UIView alloc] initWithFrame:CGRectMake(12, y, cw-24, 64)];
        row.backgroundColor = [UIColor secondarySystemBackgroundColor];
        row.layer.cornerRadius = 10;
        UILabel *t = [[UILabel alloc] initWithFrame:CGRectMake(10, 4, cw-90, 36)];
        NSString *modeS = [@[@"orig",@"nil",@"str:"] objectAtIndex:MIN([r[@"mode"] intValue],2)];
        t.text = [NSString stringWithFormat:@"%@\n%@ → %@%@", r[@"class"], r[@"selector"], modeS, [r[@"mode"] intValue]==2 ? r[@"value"] : @""];
        t.font = [UIFont systemFontOfSize:11]; t.numberOfLines = 2; [row addSubview:t];
        UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(cw-24-60, 16, 51, 31)];
        sw.on = [r[@"enabled"] boolValue]; sw.tag = [g_objcHooks indexOfObject:r];
        [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCHookToggle:") forControlEvents:UIControlEventValueChanged];
        [row addSubview:sw];
        UIButton *del = [UIButton buttonWithType:UIButtonTypeSystem];
        del.frame = CGRectMake(cw-24-18, 44, 22, 18); del.tag = [g_objcHooks indexOfObject:r];
        [del setTitle:@"✕" forState:UIControlStateNormal]; del.titleLabel.font = [UIFont systemFontOfSize:12];
        [del addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCHookDelTapped:") forControlEvents:UIControlEventTouchUpInside];
        [row addSubview:del];
        // v2.6.79: 点按 cell = 编辑(载入表单)；左滑 = 删除(同 keychain 列表交互)
        row.tag = [g_objcHooks indexOfObject:r];
        UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCHookEditTapped:")];
        [row addGestureRecognizer:tap];
        UISwipeGestureRecognizer *swipe = [[UISwipeGestureRecognizer alloc] initWithTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCHookSwipeDel:")];
        swipe.direction = UISwipeGestureRecognizerDirectionLeft;
        [row addGestureRecognizer:swipe];
        [sv addSubview:row]; y += 72;
    }
    sv.contentSize = CGSizeMake(cw, y + 20);
    // v2.6.45: 缺失的 push——页面从未显示(「点不动」真凶)
    [page setAccessibilityIdentifier:@"mf_objcrules"];
    mfPushPage(page);
}

// v2.6.42: MFClassDump 左滑「方法监控」入口的 C 函数别名 → 指向 ObjC 规则页
void mfShowMethodTracePage(void) {
    mfShowObjCHookPage();
}

#pragma mark - 🧪 强制 sandbox(v2.6.51: dump 挖到官方私有 API)
// [[SKPaymentQueue defaultQueue] forceSandboxForBundleIdentifier:untilDate:]
// storekitd 配合强制 bundle 走 sandbox——比进程内任何伪装都正
void mfObjCForceSandboxTapped(void) {
    id q = nil;
    Class qcls = objc_getClass("SKPaymentQueue");
    if (qcls) q = ((id(*)(id,SEL))objc_msgSend)((id)qcls, NSSelectorFromString(@"defaultQueue"));
    SEL sel = NSSelectorFromString(@"forceSandboxForBundleIdentifier:untilDate:");
    if (q && [q respondsToSelector:sel]) {
        ((void(*)(id,SEL,NSString*,NSDate*))objc_msgSend)(q, sel,
            mfCurrentBundleId(), [NSDate dateWithTimeIntervalSinceNow:365*24*3600]);
        OH_LOG(@"forceSandbox requested for %@", mfCurrentBundleId());
        mfToast(@"🧪 已强制 sandbox——重启 App 点购买验证");
    } else {
        OH_LOG(@"forceSandbox selector missing");
        mfToast(@"SDK 不支持此接口");
    }
}

#pragma mark - 🧪 伪造交易实验(v2.6.52)
// 目标: hook SKPaymentQueue#transactions 返回伪造已购数组(通用 SK1 解锁)
// 本按钮: 运行时构造 SKPaymentTransaction 并读写验证——ivar 布局 dump 有, 壳层转发未证实
#include <string.h>
void mfObjCTxProbeTapped(void) {
    // 1. 枚举 SKPaymentTransaction 类 ivar(转发路径真相)
    Class TT = objc_getClass("SKPaymentTransaction");
    unsigned int n = 0;
    Ivar *ivs = class_copyIvarList(TT, &n);
    OH_LOG(@"TX ivars: %u", n);
    for (unsigned int i = 0; i < n; i++) {
        OH_LOG(@"  ivar %s off=%ld", ivar_getName(ivs[i]), (long)ivar_getOffset(ivs[i]));
    }
    free(ivs);
    // 2. 构造 internal + 直接写 scalar/对象 ivar
    // v2.6.53: class_createInstance 绕过 alloc/init——SK 内部类 init 可能连 XPC/断言(闪退点)
    Class TI = objc_getClass("SKPaymentTransactionInternal");
    if (!TI) { OH_LOG(@"Internal class missing"); return; }
    OH_LOG(@"probe: creating internal via class_createInstance");
    id ti = class_createInstance(TI, 0);
    OH_LOG(@"probe: internal=%@", ti);
    Ivar stI = class_getInstanceVariable(TI, "__transactionState");
    if (stI) { long long st = 1; memcpy((char *)(__bridge void *)ti + ivar_getOffset(stI), &st, 8); }
    Ivar payI = class_getInstanceVariable(TI, "__payment");
    // 3. 构造 SKPayment(Internal) 填 productIdentifier(同样绕过 init)
    Class PI = objc_getClass("SKPaymentInternal");
    id pi = nil;
    if (PI) pi = class_createInstance(PI, 0);
    if (pi) {
        Ivar pidI = class_getInstanceVariable(PI, "__productIdentifier");
        if (pidI) object_setIvar(pi, pidI, @"com.sugarmo.ScrollClip.pro");
    }
    OH_LOG(@"probe: payment built=%@", pi);
    if (payI && pi) object_setIvar(ti, payI, pi);
    // 4. 包壳: SKPaymentTransaction class_createInstance 后塞 internal
    OH_LOG(@"probe: creating SKPaymentTransaction shell");
    id tx = class_createInstance(TT, 0);
    Ivar intI = class_getInstanceVariable(TT, "_internal");
    if (intI) object_setIvar(tx, intI, ti);
    Ivar intI2 = class_getInstanceVariable(TT, "__internal");
    if (intI2) object_setIvar(tx, intI2, ti);
    OH_LOG(@"probe: shell=%@", tx);
    // 5. 读写验证(修正: transaction 无 productIdentifier — pid 在 payment 上)
    long long st2 = ((long long(*)(id,SEL))objc_msgSend)(tx, NSSelectorFromString(@"transactionState"));
    id pay2 = ((id(*)(id,SEL))objc_msgSend)(tx, NSSelectorFromString(@"payment"));
    NSString *pid2 = nil;
    if (pay2) pid2 = ((id(*)(id,SEL))objc_msgSend)(pay2, NSSelectorFromString(@"productIdentifier"));
    OH_LOG(@"probe: state=%lld pid=%@", st2, pid2);
}

#pragma mark - 编辑
// v2.6.47: 页面内表单添加(替代弹窗)——直接读表单字段
void mfObjCHookFormAddTapped(void) {
    if (!g_clsF) { OH_LOG(@"form not ready"); return; }
    int mode = (int)g_modeSeg.selectedSegmentIndex; // 0=透传 1=nil 2=str 3=观察
    id val = mode == 2 ? (g_valF.text ?: @"") : nil;
    mfObjCHookPersist(g_clsF.text, g_selF.text, mode, val);
}

void mfObjCHookPersist(NSString *cls, NSString *sel, int mode, id val) {
    OH_LOG(@"persist: cls=%@ sel=%@ mode=%d val=%@", cls, sel, mode, val);
    if (cls.length == 0 || sel.length == 0) { mfToast(@"类名和方法必填"); return; }
    NSDictionary *newRule = @{@"class": cls, @"selector": sel, @"mode": @(mode), @"value": (val ?: @""), @"enabled": @YES};
    // v2.6.79: 点 cell 编辑后 → 更新原规则；否则追加新规则
    if (g_editIdx >= 0 && g_editIdx < (NSInteger)g_objcHooks.count) {
        g_objcHooks[g_editIdx] = newRule;
        g_editIdx = -1;
        OH_LOG(@"persist: updated rule at index (edit mode)");
    } else {
        [g_objcHooks addObject:newRule];
    }
    mfObjCHookSave();
    mfObjCHookApply();
    // rebuild 列表
    if ([[(UIView *)g_mfPages.lastObject accessibilityIdentifier] isEqualToString:@"mf_objcrules"]) {
        UIView *top = g_mfPages.lastObject;
        [top removeFromSuperview];
        [g_mfPages removeLastObject];
    }
    mfShowObjCHookPage();
}

// v2.6.79: 点 cell 载入编辑表单
void mfObjCHookEditTappedFromView(UIView *row) {
    NSInteger idx = row.tag;
    if (idx < 0 || idx >= (NSInteger)g_objcHooks.count) return;
    NSDictionary *r = g_objcHooks[idx];
    g_editIdx = idx;
    if (g_clsF) g_clsF.text = r[@"class"] ?: @"";
    if (g_selF) g_selF.text = r[@"selector"] ?: @"";
    if (g_modeSeg) g_modeSeg.selectedSegmentIndex = MIN([r[@"mode"] intValue], 4);
    if (g_valF) g_valF.text = r[@"value"] ?: @"";
    mfToast(@"✏️ 已载入到表单，改完点➕添加会更新该规则");
    OH_LOG(@"edit tapped: idx=%ld class=%@", (long)idx, r[@"class"]);
}

// v2.6.79: 左滑删除规则
void mfObjCHookSwipeDelFromView(UIView *row) {
    NSInteger idx = row.tag;
    if (idx < 0 || idx >= (NSInteger)g_objcHooks.count) return;
    [g_objcHooks removeObjectAtIndex:idx];
    mfObjCHookSave();
    mfObjCHookApply();
    mfToast(@"🗑 已删除规则");
    if ([[(UIView *)g_mfPages.lastObject accessibilityIdentifier] isEqualToString:@"mf_objcrules"]) {
        UIView *top = g_mfPages.lastObject;
        [top removeFromSuperview];
        [g_mfPages removeLastObject];
    }
    mfShowObjCHookPage();
}

void mfObjCHookToggle(UISwitch *sw) {
    NSInteger idx = sw.tag;
    if (idx < 0 || idx >= g_objcHooks.count) return;
    NSMutableDictionary *r = [g_objcHooks[idx] mutableCopy];
    r[@"enabled"] = @(sw.on);
    g_objcHooks[idx] = r;
    mfObjCHookSave();
    [g_hookRestore removeAllObjects]; g_hookOn = NO;
    mfObjCHookApply();
}

void mfObjCHookDelTapped(UIButton *b) {
    NSInteger idx = b.tag;
    if (idx < 0 || idx >= g_objcHooks.count) return;
    [g_objcHooks removeObjectAtIndex:idx];
    mfObjCHookSave();
    [g_hookRestore removeAllObjects]; g_hookOn = NO;
    // v2.6.45: 弹旧页重建
    if ([[(UIView *)g_mfPages.lastObject accessibilityIdentifier] isEqualToString:@"mf_objcrules"]) {
        UIView *top = g_mfPages.lastObject;
        [top removeFromSuperview];
        [g_mfPages removeLastObject];
    }
    mfShowObjCHookPage();
}

#pragma mark - ⚡ SK1 通杀(v2.6.55)
// 通用: hook SKPaymentQueue#transactions + SK 交易 getter 读取层
//   无真实交易时返回伪造数组(每个已验证 pid 一条 fakeTx) —— app 遍历判断解锁通杀
//   有真实交易时透传原值(不干扰正常购买流程)
static BOOL g_sk1on = NO;
extern NSArray *mfSubPids(void); // MFSubInject.m — 过滤+Top置顶后的商品 ID

// v2.17.0: SK1 通杀引擎整体移除(用户裁定: SK1 假交易对 SwiftyStoreKit 收据验证类 app 无效, 非通杀)
// 判定接管(mfJudgeTakeover)同日移除 — MOSubscriptionCenter/PARSubscriptionStatus 为系统类, 与 app 无关

// ====== v2.6.71 方法定位器：全类扫描 selector → 宿主类名(混淆 app 判定方法定位) ======

NSArray *mfFindClassesForSelector(NSString *selName) {
    SEL target = NSSelectorFromString(selName);
    if (!target) return @[];
    NSMutableArray *hits = [NSMutableArray array];
    int nClasses = objc_getClassList(NULL, 0);
    Class *buffer = (Class *)malloc(sizeof(Class) * nClasses);
    objc_getClassList(buffer, nClasses);
    for (int i = 0; i < nClasses; i++) {
        Class cls = buffer[i];
        const char *clsName = class_getName(cls);
        if (!clsName || strncmp(clsName, "NS", 2) == 0) continue;
        if (strncmp(clsName, "UI", 2) == 0) continue;
        if (strncmp(clsName, "__", 2) == 0) continue;   // 只跳系统双下划线私有; _TtC 开头的 Swift 主类必须保留!
        // v2.6.72: 关键——绝不用 instancesRespondToSelector:/respondsToSelector:(会对脆类触发消息转发 → SIGTRAP,
        //          实测 131944.ips ___forwarding___ crash)。只查 objc runtime 方法表(class_getInstanceMethod),
        //          不产生任何消息发送, 对随意类安全。
        BOOL isInst = class_getInstanceMethod(cls, target) != NULL;
        BOOL isClass = class_getClassMethod(cls, target) != NULL;
        if (isInst || isClass) {
            [hits addObject:@{@"class": @(clsName), @"kind": isClass ? @"类方法" : @"实例方法"}];
        }
    }
    free(buffer);
    return hits;
}

static NSString *g_locatorSel = @"";

// 定位页控制器
@interface MFSelectorLocator : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *results;
@property (nonatomic, weak) UITableView *table;
@property (nonatomic, weak) UILabel *stateLabel;
@property (nonatomic, weak) UITextField *tf;
@end
@implementation MFSelectorLocator
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return (NSInteger)self.results.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *rid = @"loc2";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:rid];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:rid];
    NSDictionary *r = self.results[ip.row];
    c.textLabel.text = r[@"class"];
    c.textLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightMedium];
    c.detailTextLabel.text = r[@"kind"];
    c.detailTextLabel.font = [UIFont systemFontOfSize:10];
    c.backgroundColor = UIColor.clearColor;
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    NSDictionary *r = self.results[ip.row];
    // 生成 ObjC 规则(强制返回 YES): class + selector + mode=强制返回
    mfObjCHookPersist(r[@"class"], g_locatorSel, 1, nil);
    mfToast([NSString stringWithFormat:@"✅ 规则: %@ %@", r[@"class"], g_locatorSel]);
    mfPopPage();
    mfPopPage();
}
@end

void mfShowSelectorLocatorPage(void) {
    UIView *page = mfMakePage(@"定位方法", YES);
    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 32, 34)];
    hint.text = @"输入 selector(如 canLicenseunzfj:)，扫全类找宿主类名。点击命中类→自动建强制返回YES规则。";
    hint.font = [UIFont systemFontOfSize:11];
    hint.textColor = [UIColor secondaryLabelColor];
    hint.numberOfLines = 3;
    [page addSubview:hint];

    UITextField *tf = [[UITextField alloc] initWithFrame:CGRectMake(16, 86, g_mfCardW - 32, 36)];
    tf.borderStyle = UITextBorderStyleRoundedRect;
    tf.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tf.autocorrectionType = UITextAutocorrectionTypeNo;
    tf.text = g_locatorSel.length ? g_locatorSel : @"canLicenseunzfj:";
    mfAttachKbBar(tf);   // v2.7.1: 键盘收起工具条
    [page addSubview:tf];

    UIButton *scanBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    scanBtn.frame = CGRectMake(16, 128, g_mfCardW - 32, 36);
    [scanBtn setTitle:@"🔍 扫描" forState:UIControlStateNormal];
    scanBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    scanBtn.backgroundColor = [UIColor systemBlueColor];
    scanBtn.tintColor = UIColor.whiteColor;
    scanBtn.layer.cornerRadius = 8;
    objc_setAssociatedObject(scanBtn, "locTF", tf, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [scanBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCLocateScan:") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:scanBtn];

    UILabel *state = [[UILabel alloc] initWithFrame:CGRectMake(16, 170, g_mfCardW - 32, 18)];
    state.text = @"";
    state.font = [UIFont systemFontOfSize:11];
    state.textColor = [UIColor secondaryLabelColor];
    [page addSubview:state];

    UITableView *tb = [[UITableView alloc] initWithFrame:CGRectMake(0, 192, g_mfCardW, g_mfCardH - 192)
                                                   style:UITableViewStylePlain];
    tb.backgroundColor = UIColor.clearColor;
    [page addSubview:tb];

    MFSelectorLocator *loc = [[MFSelectorLocator alloc] init];
    loc.table = tb; loc.stateLabel = state; loc.tf = tf;
    tb.dataSource = loc; tb.delegate = loc;
    objc_setAssociatedObject(page, "locator", loc, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    mfPushPage(page);
}

void mfRunSelectorLocatorFromButton(UIButton *btn) {
    UITextField *tf = objc_getAssociatedObject(btn, "locTF");
    if (!tf) return;
    NSString *sel = [tf.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (sel.length == 0) { mfToast(@"⚠️ 输入 selector"); return; }
    g_locatorSel = sel;
    OH_LOG(@"locator scan: %@", sel);
    UIView *pg = tf;
    while (pg && !objc_getAssociatedObject(pg, "locator")) pg = pg.superview;
    MFSelectorLocator *loc = objc_getAssociatedObject(pg, "locator");
    if (!loc) return;
    loc.stateLabel.text = [NSString stringWithFormat:@"🔍 扫描 %@ …", sel];
    NSArray *hits = mfFindClassesForSelector(sel);
    loc.results = hits;
    [loc.table reloadData];
    loc.stateLabel.text = [NSString stringWithFormat:@"命中 %lu 个类（点击建规则）", (unsigned long)hits.count];
    OH_LOG(@"locator: %lu hits", (unsigned long)hits.count);
    if (hits.count == 0) {
        // v2.6.74 诊断：0 命中时 dump 所有 app 相关类(Scroll/Clip/sugarmo/Picsew/App)+ 每类方法数+目标命中，定位 Swift 宿主
        int nc = objc_getClassList(NULL, 0);
        Class *buf = (Class *)malloc(sizeof(Class) * nc);
        objc_getClassList(buf, nc);
        for (int i = 0; i < nc; i++) {
            const char *nm = class_getName(buf[i]);
            if (!nm) continue;
            NSString *nn = @(nm);
            BOOL rel = [nn containsString:@"Scroll"] || [nn containsString:@"sugarmo"] || [nn containsString:@"Picsew"] || [nn containsString:@"App"] || [nn containsString:@"TtC9"];
            if (!rel) continue;
            unsigned mc_inst = 0, mc_cls = 0;
            Method *mi = class_copyMethodList(buf[i], &mc_inst);
            free(mi);
            Method *mc = class_copyMethodList(objc_getMetaClass(nm), &mc_cls);
            free(mc);
            BOOL hasTarget = class_getInstanceMethod(buf[i], NSSelectorFromString(g_locatorSel)) != NULL
                          || class_getClassMethod(buf[i], NSSelectorFromString(g_locatorSel)) != NULL;
            OH_LOG(@"loc-diag: %s inst=%u cls=%u target=%@", nm, mc_inst, mc_cls, hasTarget ? @"YES" : @"no");
        }
        free(buf);
        OH_LOG(@"loc-diag: total classes=%d", nc);
    }
}

// ====== v2.6.76 Defaults 浏览器：纯读取当前 app 的 NSUserDefaults 全 key（零 hook，无崩溃风险） ======

@interface MFDefaultsBrowser : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *entries; // [{k,v}]
@property (nonatomic, weak) UITableView *table;
@property (nonatomic, weak) UILabel *stateLabel;
@end
@implementation MFDefaultsBrowser
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return (NSInteger)self.entries.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *rid = @"dbr";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:rid];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:rid];
    NSDictionary *e = self.entries[ip.row];
    c.textLabel.text = e[@"k"];
    c.textLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightMedium];
    c.textLabel.adjustsFontSizeToFitWidth = YES;
    c.detailTextLabel.text = e[@"v"];
    c.detailTextLabel.font = [UIFont systemFontOfSize:10];
    c.detailTextLabel.numberOfLines = 2;
    c.backgroundColor = UIColor.clearColor;
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    NSDictionary *e = self.entries[ip.row];
    NSString *copyText = [NSString stringWithFormat:@"%@ = %@", e[@"k"], e[@"v"]];
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    pb.string = copyText;
    mfToast([NSString stringWithFormat:@"✅ %@ = %@", e[@"k"], e[@"v"]]);
}
@end

void mfShowDefaultsBrowserPage(void) {
    UIView *page = mfMakePage(@"Defaults 浏览器", YES);
    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 32, 30)];
    hint.text = @"当前 App 的 NSUserDefaults 全 key（判定读的 key 必在其中）。点行复制 key=value。";
    hint.font = [UIFont systemFontOfSize:11];
    hint.textColor = [UIColor secondaryLabelColor];
    hint.numberOfLines = 2;
    [page addSubview:hint];
    
    UILabel *state = [[UILabel alloc] initWithFrame:CGRectMake(16, 78, g_mfCardW - 32, 18)];
    state.text = @"读取中…";
    state.font = [UIFont systemFontOfSize:11];
    state.textColor = [UIColor secondaryLabelColor];
    [page addSubview:state];
    
    UITableView *tb = [[UITableView alloc] initWithFrame:CGRectMake(0, 100, g_mfCardW, g_mfCardH - 100) style:UITableViewStylePlain];
    tb.backgroundColor = UIColor.clearColor;
    [page addSubview:tb];
    
    MFDefaultsBrowser *br = [[MFDefaultsBrowser alloc] init];
    br.table = tb; br.stateLabel = state;
    tb.dataSource = br; tb.delegate = br;
    objc_setAssociatedObject(page, "dbr", br, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    mfPushPage(page);
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSDictionary *dict = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        NSMutableArray *arr = [NSMutableArray array];
        for (NSString *k in dict) {
            id v = dict[k];
            NSString *vs;
            if ([v isKindOfClass:[NSString class]]) vs = v;
            else if ([v isKindOfClass:[NSNumber class]]) vs = [(NSNumber *)v stringValue];
            else if ([v isKindOfClass:[NSData class]]) vs = [NSString stringWithFormat:@"<data %lu>", (unsigned long)[(NSData *)v length]];
            else if ([v isKindOfClass:[NSArray class]] || [v isKindOfClass:[NSDictionary class]]) vs = [NSString stringWithFormat:@"<%@ %lu>", NSStringFromClass([v class]), (unsigned long)[v count]];
            else if ([v isKindOfClass:[NSDate class]]) vs = [NSString stringWithFormat:@"<date %@>", v];
            else vs = [v description] ?: @"(nil)";
            if (vs.length > 160) vs = [vs substringToIndex:160];
            [arr addObject:@{@"k": k, @"v": vs}];
        }
        NSArray *sorted = [arr sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            return [a[@"k"] compare:b[@"k"] options:NSCaseInsensitiveSearch];
        }];
        dispatch_async(dispatch_get_main_queue(), ^{
            br.entries = sorted;
            [tb reloadData];
            state.text = [NSString stringWithFormat:@"共 %lu 个 key（点行复制）", (unsigned long)sorted.count];
            OH_LOG(@"defaults browser: %lu keys", (unsigned long)sorted.count);
            if (sorted.count == 0) state.text = @"无数据（该 app 未写 defaults）";
        });
    });
}
