// MFSwiftInstance.m — 运行时实例写 (v2.58.100)
//
// ★ 用户指摘修正: 之前这里自己 objc_copyClassList 找类 + 全堆 vm_region 扫描找实例
//   —— 两条都是重复造轮子。现在:
//     ① 类/字段偏移: **由侦查(ivargate)喂入** — 它本来就用 objc_copyClassList +
//        class_copyIvarList 找到了 (mf_debug_94: HMVipProManager._isVipPro off=1744)。
//     ② 实例: **从 app 已有对象图遍历得到** — 不走堆扫描。
//        classdump 实测有 10 个 UI 类型持有 _vipProManager (HMRootView / IPTVPlayerRootView /
//        SettingVipBanner / VIPDetailPage ...), 从 keyWindow 的视图控制器递归遍历
//        ivar 就能拿到那个对象, 不需要知道它分配到哪块内存。
//
// 本模块只做侦查和 F9 都没做的事: 拿到实例后写它的 bool 字段(先读回验证)。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <string.h>
#import <mach/mach.h>
#import "MFPanel.h"

static Class g_entCls = NULL;
static char g_entIvar[128] = {0};
static ptrdiff_t g_entOff = -1;

// 侦查喂入目标 (MFRecon 的 ivargate 块调用)
void mfEntClsTargetSet(Class c, const char *ivarName, ptrdiff_t off) {
    if (!c || !ivarName || !*ivarName) return;
    if (g_entCls && g_entOff >= 0) return;          // 首个命中优先, 幂等
    g_entCls = c;
    strncpy(g_entIvar, ivarName, sizeof(g_entIvar) - 1);
    g_entOff = off;
    mfLog(@"[inst] 目标已就绪(来自侦查): %s.%s off=%ld",
          class_getName(c), ivarName, (long)off);
}

static BOOL mfiRd(uintptr_t a, void *dst, size_t len) {
    if (!a || !len) return NO;
    vm_size_t got = 0;
    return vm_read_overwrite(mach_task_self(), (vm_address_t)a, (vm_size_t)len,
                             (vm_address_t)dst, &got) == KERN_SUCCESS && got == len;
}
static BOOL mfiWr(uintptr_t a, const void *src, size_t len) {
    if (!a || !len) return NO;
    return vm_write(mach_task_self(), (vm_address_t)a, (vm_address_t)src,
                    (mach_msg_type_number_t)len) == KERN_SUCCESS;
}

// =====================================================================
// 从对象图里找目标类的实例 —— 复用 app 自己的引用链, 不做盲扫。
//   起点: keyWindow.rootViewController (以及其 presentedViewController 链)
//   方式: 递归遍历对象的全部 ivar (对象引用型), 深度/数量都有上限。
//   安全: 只读 ivar 指针值; 指针是否有效由后续 mfiRd 判定, 不 deref。
// =====================================================================
static int mfiWalk(id root, Class want, void **out, int cap, int depth, int *budget) {
    if (!root || !want || depth > 6 || *budget <= 0) return 0;
    int n = 0;
    *budget -= 1;

    if (object_getClass(root) == want) { if (n < cap) out[n++] = (__bridge void *)root; return n; }

    unsigned int nIv = 0;
    Ivar *ivs = class_copyIvarList(object_getClass(root), &nIv);
    for (unsigned int i = 0; ivs && i < nIv && n < cap; i++) {
        const char *ty = ivar_getTypeEncoding(ivs[i]);
        if (!ty || ty[0] != '@') continue;           // 只看对象引用字段
        uintptr_t slot = (uintptr_t)(__bridge void *)root + (uintptr_t)ivar_getOffset(ivs[i]);
        // ★ 走 vm_read 读槽位, 不直接 deref — 槽里可能是任意位模式
        uintptr_t p = 0;
        if (!mfiRd(slot, &p, sizeof(p)) || !p) continue;
        // 再验一步: 候选对象的 isa 必须可读(说明它确实是个有效对象)
        uintptr_t isa = 0;
        if (!mfiRd(p, &isa, sizeof(isa)) || !isa) continue;
        id child = (__bridge id)(void *)p;
        int m = mfiWalk(child, want, out + n, cap - n, depth + 1, budget);
        n += m;
    }
    if (ivs) free(ivs);
    return n;
}

// 收集实例: 从关键窗口的控制器树出发
static int mfiCollectInstances(Class want, void **out, int cap) {
    int n = 0;
    int budget = 4000;                                // 遍历步数上限, 防跑飞
    NSMutableArray *roots = [NSMutableArray array];
    for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
        if (![sc isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *w in ((UIWindowScene *)sc).windows) {
            if (w.rootViewController) [roots addObject:w.rootViewController];
        }
    }
    UIWindow *kw = [UIApplication sharedApplication].keyWindow;
    if (kw.rootViewController) [roots addObject:kw.rootViewController];
    mfLog(@"[inst] 遍历起点: %lu 个根控制器", (unsigned long)roots.count);

    for (id r in roots) {
        if (n >= cap) break;
        // 同时沿 presentedViewController 链找
        id cur = r;
        int guard = 0;
        while (cur && guard++ < 8 && n < cap) {
            n += mfiWalk(cur, want, out + n, cap - n, 0, &budget);
            cur = [(UIViewController *)cur presentedViewController];
        }
    }
    return n;
}

// =====================================================================
// 对外: 侦查(只读)
// =====================================================================
NSDictionary *mfInstProbe(void) {
    if (!g_entCls || g_entOff < 0) {
        mfLog(@"[inst] 尚未定位权益类/ivar — 请先跑一次侦查(ivargate 会喂入目标)");
        return nil;
    }
    Class c = g_entCls;
    const char *cn = class_getName(c);
    mfLog(@"[inst] 目标(来自侦查): %s.%s off=%ld", cn, g_entIvar, (long)g_entOff);

    void *found[64];
    int n = mfiCollectInstances(c, found, 64);
    mfLog(@"[inst] 对象图遍历完成: 实例=%d", n);

    NSMutableArray *vals = [NSMutableArray array];
    for (int i = 0; i < n && i < 12; i++) {
        uint8_t b = 0;
        if (mfiRd((uintptr_t)found[i] + (uintptr_t)g_entOff, &b, 1)) [vals addObject:@(b)];
        mfLog(@"[inst]   #%d @%p  %s=%u", i, found[i], g_entIvar, (unsigned)b);
    }
    return @{@"cls": @(cn), @"count": @(n), @"off": @(g_entOff), @"vals": vals};
}

// =====================================================================
// 对外: 写 — 把实例的 bool 字段置 1 (先读回验证)
// =====================================================================
int mfInstForceBool(void) {
    if (!g_entCls || g_entOff < 0) {
        mfLog(@"[inst] 写: 尚未定位权益类/ivar — 请先跑一次侦查");
        return -1;
    }
    void *found[64];
    int n = mfiCollectInstances(g_entCls, found, 64);
    if (!n) { mfLog(@"[inst] 写: 对象图中未找到实例(可能尚未创建)"); return 0; }

    int ok = 0;
    for (int i = 0; i < n; i++) {
        uintptr_t a = (uintptr_t)found[i] + (uintptr_t)g_entOff;
        uint8_t old = 0;
        if (!mfiRd(a, &old, 1)) continue;
        if (old == 1) { ok++; continue; }               // 已是解锁态
        uint8_t one = 1;
        if (!mfiWr(a, &one, 1)) { mfLog(@"[inst]   #%d 写失败 @%#lx", i, (unsigned long)a); continue; }
        uint8_t back = 0;
        BOOL land = mfiRd(a, &back, 1) && back == 1;
        mfLog(@"[inst]   #%d @%#lx %s: %u→%u %@", i, (unsigned long)a, g_entIvar,
              (unsigned)old, (unsigned)back, land ? @"✓已写入" : @"✗写后读回不符");
        if (land) ok++;
    }
    mfLog(@"[inst] 写完成: %d/%d 实例已置 %s=1", ok, n, g_entIvar);
    return ok;
}
