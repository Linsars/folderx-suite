// MFSwiftInstance.m — 运行时实例写 (v2.58.103)
//
// ★ 三次路线修正的血泪史(别再走弯路):
//   v2.58.97-99: vm_region 全堆扫描找实例 —— 对的, 但类/ivar 自己查了一遍(与 ivargate 重复)
//   v2.58.101-102: 删掉重复的类查找(改由侦查喂入)——对; 但顺手把找实例也换成了
//                  对象图遍历 —— **错**: 持有 _vipProManager 的 10 个类型在 classdump
//                  产物里全是 struct(HMRootView/SettingVipBanner/VipLogoView...),
//                  不在 ObjC 对象图里, 从 UIViewController 根本走不到。
//                  mf_debug_96 实测: 遍历起点 4 个根控制器 → 实例=0。
//   v2.58.103: 类/偏移仍由侦查喂入(不重复造轮子); 找实例改回内存扫描。
//
// 为什么内存扫描是必需的(不是偷懒): Swift struct 持有的 @StateObject/@ObservedObject
//   实例在堆上, 其 isa == 类指针。ObjC runtime 不提供"某类的全部实例"API,
//   只能扫可读写区找「首字 == 类指针 且 16 字节对齐」(arm64 malloc 16 对齐)。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <string.h>
#import <mach/mach.h>
#import "MFPanel.h"

static Class g_entCls = NULL;
static char g_entIvar[128] = {0};
static ptrdiff_t g_entOff = -1;

// 侦查喂入目标 (MFRecon 的 ivargate 块调用) — 类/偏移一律复用, 不自己查
void mfEntClsTargetSet(Class c, const char *ivarName, ptrdiff_t off) {
    if (!c || !ivarName || !*ivarName) return;
    if (g_entCls && g_entOff >= 0) return;          // 首个命中优先, 幂等
    g_entCls = c;
    strncpy(g_entIvar, ivarName, sizeof(g_entIvar) - 1);
    g_entOff = off;
    mfLog(@"[inst] 目标已就绪(来自侦查): %s.%s off=%ld",
          class_getName(c), ivarName, (long)off);
}

// =====================================================================
// v2.58.104: 侦查卡收集的实例地址(持久层) — 实验页只读, 不再自己扫
// =====================================================================
static uintptr_t g_instAddrs[64];
static int g_instN = 0;

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
// 找实例: 扫可读写区, 定位 isa 指向目标类的堆对象
// =====================================================================
// ★ v2.58.104 修误报(mf_debug_97 实测 43 个全假):
//   旧判据「首字 == 类指针」在 **arm64e 上必然误报** —— 实例的 isa 是
//   PAC 签名指针, 与类元数据地址**不相等**; 而内存里到处存着类的**裸指针**
//   (objc 类表条目/元数据自引用/全局变量), 这些全被误当成实例。
//   日志铁证: _isVipPro 是 Bool, 但读出 64/112/255/104 → 那些位置不是对象。
//   正解: 用 object_getClass() 解 PAC 签名后比较, 只认真对象。
static int mfiCollectInstances(Class want, uintptr_t *out, int cap, size_t budget) {
    if (!want) return 0;
    int n = 0;
    vm_address_t addr = 0;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t infoCnt;
    mach_port_t objName = MACH_PORT_NULL;
    uint8_t buf[65536];
    int guard = 0;
    size_t scanned = 0;

    while (n < cap && guard++ < 100000) {
        infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
        kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info, &infoCnt, &objName);
        if (kr != KERN_SUCCESS) break;
        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE)) {
            uintptr_t p = (uintptr_t)addr;
            uintptr_t endp = (uintptr_t)addr + size;
            while (p + 16 <= endp && n < cap && scanned < budget) {
                size_t want2 = sizeof(buf);
                if (p + want2 > endp) want2 = (size_t)(endp - p);
                if (want2 < 16) break;
                vm_size_t got = 0;
                if (vm_read_overwrite(mach_task_self(), (vm_address_t)p, (vm_size_t)want2,
                                      (vm_address_t)buf, &got) != KERN_SUCCESS || got < 16) {
                    p += want2; scanned += want2; continue;
                }
                for (size_t i = 0; i + 8 <= got; i += 8) {
                    uintptr_t cand = p + i;
                    if (cand & 0xF) continue;        // 实例必 16 字节对齐
                    uintptr_t v = 0;
                    memcpy(&v, buf + i, 8);
                    if (!v) continue;
                    // arm64e: 解 PAC 签名再比较 — 不再用裸指针比对
                    Class ic = object_getClass((__bridge id)(void *)cand);
                    if (ic != want) continue;
                    if (n < cap) out[n++] = cand;
                }
                scanned += got;
                p += got;
            }
        }
        addr += size;
    }
    mfLog(@"[inst] 内存扫描完成: 实例=%d (扫过 %zuMB)", n, scanned / 1024 / 1024);
    return n;
}

// =====================================================================
// 对外: 写 — 把实例的 bool 字段置 1 (先读回验证)
// =====================================================================
int mfInstForceBool(void) {
    if (!g_entOff) {
        mfLog(@"[inst] 写: 尚未定位 ivar 偏移 — 请先跑一次侦查");
        return -1;
    }
    if (!g_instN) { mfLog(@"[inst] 写: 无已定位实例 — 请先在侦查卡跑一次"); return 0; }
    int n = g_instN;

    int ok = 0;
    for (int i = 0; i < n; i++) {
        uintptr_t a = g_instAddrs[i] + (uintptr_t)g_entOff;
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

NSArray *mfInstAddrs(void) {
    NSMutableArray *a = [NSMutableArray array];
    for (int i = 0; i < g_instN; i++) [a addObject:@(g_instAddrs[i])];
    return a;
}

int mfInstCollect(Class want, size_t budgetMB) {
    if (!want) return 0;
    g_instN = mfiCollectInstances(want, g_instAddrs, 64, budgetMB * 1024 * 1024);
    for (int i = 0; i < g_instN && i < 12; i++) {
        uint8_t b = 0;
        if (mfiRd(g_instAddrs[i] + (uintptr_t)g_entOff, &b, 1))
            mfLog(@"[inst]   #%d @%#lx  %s=%u", i, (unsigned long)g_instAddrs[i], g_entIvar, (unsigned)b);
    }
    return g_instN;
}
