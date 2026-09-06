// MFSKQueueForge.m — L0 队列信任型伪造引擎 v2.49.5
// v2.49.5 两升级:
//   A) ivar 暴力映射 — 不猜名字, 对自家构造对象逐 ivar 试写+公开 getter 读回验证
//      (2.49.4 实锤: TxProbe 时代的 __transactionState/__productIdentifier 布局在本机全落空)
//   B) 真实交易翻转路 — hook observer 回调 paymentQueue:updatedTransactions:,
//      Apple 发来的 failed 交易(用户取消/断网)原地翻转为 purchased 再放行
//      = 真实对象自带合法 payment/identifier, 语义上无法与真购买区分
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <StoreKit/StoreKit.h>
#import <objc/runtime.h>
#import <string.h>
#import "MFPanel.h"

static BOOL g_l0on = NO;
static NSMutableArray<id<SKPaymentTransactionObserver>> *g_l0observers;
static NSMutableSet *g_l0swizzledCls;
static Ivar g_stIvar = nil, g_payIvar = nil, g_pidIvar = nil, g_intIvar = nil, g_idIvar = nil;
static BOOL g_mapped = NO;
static void (*g_origCb)(id, SEL, id, NSArray *);

// 安全 getter: iOS17 SKPaymentInternal 无 productIdentifier selector
// (2.49.5 全场闪退根因: 暴力映射对探针调 getter → unrecognized selector → ctor 炸)
static NSString *l0SafePid(id payment) {
    if (!payment) return nil;
    SEL sel = NSSelectorFromString(@"productIdentifier");
    if (![payment respondsToSelector:sel]) return nil;
    @try { return ((id(*)(id,SEL))objc_msgSend)(payment, sel); } @catch (...) { return nil; }
}
static long long l0SafeState(id tx) {
    if (!tx) return -1;
    SEL sel = NSSelectorFromString(@"transactionState");
    if (![tx respondsToSelector:sel]) return -1;
    @try { return ((long long(*)(id,SEL))objc_msgSend)(tx, sel); } @catch (...) { return -1; }
}

#pragma mark - ivar 暴力映射
static void l0DumpIvars(Class c, const char *tag) {
    unsigned int n = 0;
    Ivar *ivs = class_copyIvarList(c, &n);
    NSMutableString *s = [NSMutableString string];
    for (unsigned int i = 0; i < n; i++)
        [s appendFormat:@"%s@%ld ", ivar_getName(ivs[i]), (long)ivar_getOffset(ivs[i])];
    mfLog(@"[l0] ivars %s(%u): %@", tag, n, s);
    free(ivs);
}

static void l0MapIvars(void) {
    if (g_mapped) return;
    Class TT = objc_getClass("SKPaymentTransaction");
    Class TI = objc_getClass("SKPaymentTransactionInternal");
    Class PI = objc_getClass("SKPaymentInternal");
    if (!TT || !TI) { mfLog(@"[l0] map: SKPTransaction/Internal 类缺失"); return; }
    l0DumpIvars(TT, "tx");
    l0DumpIvars(TI, "txInternal");
    if (PI) l0DumpIvars(PI, "payment");

    // 探针对象: 壳 + internal
    id ti = class_createInstance(TI, 0);
    id tx = ti ? class_createInstance(TT, 0) : nil;
    if (!ti || !tx) { mfLog(@"[l0] map: createInstance 失败"); return; }

    // shell._internal
    const char *intCands[] = {"_internal", "__internal", "internal", NULL};
    SEL selPay = NSSelectorFromString(@"payment");
    for (int i = 0; intCands[i]; i++) {
        Ivar iv = class_getInstanceVariable(TT, intCands[i]);
        if (!iv) continue;
        object_setIvar(tx, iv, ti);
        id back = ((id(*)(id,SEL))objc_msgSend)(tx, selPay);   // payment getter 走 internal
        if (back || class_getInstanceVariable(TT, intCands[i])) { g_intIvar = iv; break; }
    }
    if (!g_intIvar) {
        // 按 ivar 类型 id 兜底: 第一个对象型 ivar
        unsigned int n = 0; Ivar *ivs = class_copyIvarList(TT, &n);
        for (unsigned int i = 0; i < n; i++)
            if (ivar_getTypeEncoding(ivs[i]) && ivar_getTypeEncoding(ivs[i])[0] == '@') { g_intIvar = ivs[i]; object_setIvar(tx, ivs[i], ti); break; }
        free(ivs);
    }

    // state ivar: v2.49.9 只按名精确匹配(2.49.8 事故: 暴力试写 8 字节踩 4 字节 ivar 邻居 → setIvar 后续 SEGV)
    const char *stCands[] = {"_transactionState", "__transactionState", "transactionState", NULL};
    for (int i = 0; stCands[i]; i++) {
        g_stIvar = class_getInstanceVariable(TI, stCands[i]);
        if (g_stIvar) break;
    }

    // payment ivar(internal 上)
    const char *payCands[] = {"__payment", "_payment", "payment", NULL};
    for (int i = 0; payCands[i] && !g_payIvar; i++) {
        Ivar iv = class_getInstanceVariable(TI, payCands[i]);
        if (iv) g_payIvar = iv;
    }

    // v2.49.9: pid 不映射 — SKMutablePayment 公开路自带 productIdentifier, 内部类碰都不碰

    // transactionIdentifier ivar(tx 壳上按名找, 有就用)
    const char *idCands[] = {"_transactionIdentifier", "__transactionIdentifier", "transactionIdentifier", NULL};
    for (int i = 0; idCands[i] && !g_idIvar; i++)
        g_idIvar = class_getInstanceVariable(TI, idCands[i]);   // v2.49.8: tid 在 internal 上(布局实测@64)

    g_mapped = YES;
    mfLog(@"[l0] map done: int=%s st=%s pay=%s pid=%s tid=%s",
          g_intIvar ? ivar_getName(g_intIvar) : "-",
          g_stIvar ? ivar_getName(g_stIvar) : "-",
          g_payIvar ? ivar_getName(g_payIvar) : "-",
          g_pidIvar ? ivar_getName(g_pidIvar) : "-",
          g_idIvar ? ivar_getName(g_idIvar) : "-");
}

#pragma mark - B 路: 真实 failed 交易翻转(observer 回调 hook)
static void l0_observerCb(id self, SEL _cmd, id queue, NSArray *txs) {
    if (g_l0on && g_stIvar && g_intIvar && txs.count) {
        NSMutableArray *mut = nil;
        for (id tx in txs) {
            long long st = ((long long(*)(id,SEL))objc_msgSend)(tx, NSSelectorFromString(@"transactionState"));
            if (st == 2) {   // SKPaymentTransactionStateFailed
                id internal = object_getIvar(tx, g_intIvar);
                if (internal) {
                    long long one = 1;
                    memcpy((char *)(__bridge void *)internal + ivar_getOffset(g_stIvar), &one, 8);
                    long long now = ((long long(*)(id,SEL))objc_msgSend)(tx, NSSelectorFromString(@"transactionState"));
                    id p = ((id(*)(id,SEL))objc_msgSend)(tx, NSSelectorFromString(@"payment"));
                    mfLog(@"[l0] 真实交易翻转: failed→%@ %@", now == 1 ? @"purchased ✓" : @"FAIL", l0SafePid(p) ?: @"?");
                    if (!mut) mut = [NSMutableArray arrayWithArray:txs];
                }
            }
        }
        if (mut) txs = mut;
    }
    g_origCb(self, _cmd, queue, txs);
}

#pragma mark - hooks
static void (*l0_origAddObserver)(id, SEL, id);
static void l0_addObserver(id self, SEL _cmd, id ob) {
    if (ob) {
        if (!g_l0observers) g_l0observers = [NSMutableArray array];
        if (![g_l0observers containsObject:ob]) {
            [g_l0observers addObject:ob];
            mfLog(@"[l0] observer recorded: %@", NSStringFromClass([ob class]));
            // B 路装配: swizzle 该 observer 的 paymentQueue:updatedTransactions:
            if (!g_l0swizzledCls) g_l0swizzledCls = [NSMutableSet set];
            Class cls = object_getClass(ob);
            SEL cb = @selector(paymentQueue:updatedTransactions:);
            Method m = class_getInstanceMethod(cls, cb);
            if (m && ![g_l0swizzledCls containsObject:cls]) {
                [g_l0swizzledCls addObject:cls];
                g_origCb = (void (*)(id, SEL, id, NSArray *))method_getImplementation(m);
                method_setImplementation(m, (IMP)l0_observerCb);
                mfLog(@"[l0] B 路装配: %s.paymentQueue:updatedTransactions:", class_getName(cls));   // char* 必须 %s
            }
        }
    }
    l0_origAddObserver(self, _cmd, ob);
}
static void (*l0_origAddPayment)(id, SEL, id);
static void l0_addPayment(id self, SEL _cmd, id payment) {
    if (payment) {
        NSString *pid = nil;
        @try { pid = ((id(*)(id,SEL))objc_msgSend)(payment, NSSelectorFromString(@"productIdentifier")); } @catch(...) {}
        if (pid.length) mfLog(@"[l0] addPayment: %@ (B 路等真实交易)", pid);   // 遥测
    }
    l0_origAddPayment(self, _cmd, payment);
}

#pragma mark - 门控/装配
long mfL0ObserverCount(void) { return g_l0observers ? g_l0observers.count : 0; }
BOOL mfL0IsOn(void) { return g_l0on; }

void mfL0CtorInstall(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        l0MapIvars();
        Method m1 = class_getInstanceMethod(objc_getClass("SKPaymentQueue"), @selector(addTransactionObserver:));
        Method m2 = class_getInstanceMethod(objc_getClass("SKPaymentQueue"), @selector(addPayment:));
        if (!m1 || !m2) { mfLog(@"[l0] SKPaymentQueue 方法缺失"); return; }
        l0_origAddObserver = (void (*)(id, SEL, id))method_getImplementation(m1);
        method_setImplementation(m1, (IMP)l0_addObserver);
        l0_origAddPayment = (void (*)(id, SEL, id))method_getImplementation(m2);
        method_setImplementation(m2, (IMP)l0_addPayment);
        g_l0on = [[NSUserDefaults standardUserDefaults] boolForKey:@"mfL0ForgeEnabled"];
        mfLog(@"[l0] hooks installed at ctor (restored=%d)", g_l0on);
    });
}

void mfL0SetOn(BOOL on) {
    mfL0CtorInstall();
    g_l0on = on;
    [[NSUserDefaults standardUserDefaults] setBool:on forKey:@"mfL0ForgeEnabled"];
    mfLog(@"[l0] %@ (observers=%ld)", on ? @"ARMED" : @"DISARMED", (long)mfL0ObserverCount());
}

