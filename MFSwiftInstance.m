// MFSwiftInstance.m — 运行时实例直写 (v2.58.97)
//
// 动机(六轮静态 patch 全不亮的根本反思):
//   所有失败都源于同一个结构性问题 —— **静态偏移无法区分类**。
//   0x6d0 在几百个类里都有字段, 无论用"词表+偏移"还是"函数指纹"去猜,
//   都会命中别人的代码; 补丁"字节落地"了却改在无关函数上 → 永远不亮。
//
//   换掉的假设: 不去猜"哪条指令读它", 而是**直接操作那个真实对象**。
//   dylib 就运行在 app 进程内 → 可以在堆里找到 HMVipProManager 的实例,
//   直接写它的 _isVipPro 字段。这不需要任何点位猜测, 也不改任何代码字节。
//
// 实现要点(安全第一, 全部只读扫描 + 校验后写):
//   ① 类: objc_copyClassList 按名匹配 (该 API 在 MFRecon 已证明不崩)
//   ② ivar 偏移: class_copyIvarList 按名取 (不硬编码偏移)
//   ③ 实例: 遍历可读写内存区, 逐块 vm_read_overwrite, 找 16 字节对齐且
//      首字 == 类指针 的位置 (arm64 malloc 返回 16 字节对齐 → 极大降低误报)
//   ④ 写: 先读回原值并记录(new/old 都进日志), 写完再读回验证
//   ★ 单次扫描有预算上限, 不阻塞主线程; 全部读走 vm_read_overwrite, 越界不崩

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <string.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import "MFPanel.h"

#define MFI_MAX_INST 64

// ---- 按名找类 ----
static Class mfiFindClass(const char *sub) {
    if (!sub || !*sub) return NULL;
    unsigned n = 0;
    Class res = NULL;
    Class *list = objc_copyClassList(&n);
    if (!list) return NULL;
    for (unsigned i = 0; i < n; i++) {
        const char *nm = class_getName(list[i]);
        if (nm && strstr(nm, sub)) { res = list[i]; break; }
    }
    free(list);
    return res;
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

// ---- 找实例: 首字 == 类指针 且 16 字节对齐 ----
static int mfiScan(uintptr_t wantCls, uintptr_t *out, int cap, size_t budget) {
    int n = 0;
    vm_address_t addr = 0;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t infoCnt;
    mach_port_t objName = MACH_PORT_NULL;
    size_t scanned = 0;
    uint8_t buf[65536];

    while (n < cap && scanned < budget) {
        infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
        kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info, &infoCnt, &objName);
        if (kr != KERN_SUCCESS) break;
        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE)) {
            uintptr_t p = (uintptr_t)addr;
            uintptr_t endp = (uintptr_t)addr + size;
            while (p + 16 <= endp && n < cap && scanned < budget) {
                size_t want = sizeof(buf);
                if (p + want > endp) want = (size_t)(endp - p);
                if (want < 16) break;
                vm_size_t got = 0;
                if (vm_read_overwrite(mach_task_self(), (vm_address_t)p, (vm_size_t)want,
                                      (vm_address_t)buf, &got) != KERN_SUCCESS || got < 16) break;
                for (size_t i = 0; i + 8 <= got; i += 8) {
                    uintptr_t v = 0;
                    memcpy(&v, buf + i, 8);
                    if (v != wantCls) continue;
                    uintptr_t cand = p + i;
                    if (cand & 0xF) continue;              // 实例必 16 字节对齐
                    if (n < cap) out[n++] = cand;
                }
                scanned += got;
                p += got;
            }
        }
        addr += size;
    }
    return n;
}

// ---- 取 ivar 偏移(按名) ----
static ptrdiff_t mfiIvarOff(Class c, const char *name, const char **typeOut) {
    unsigned n = 0;
    Ivar *ivs = class_copyIvarList(c, &n);
    ptrdiff_t off = -1;
    for (unsigned i = 0; ivs && i < n; i++) {
        const char *in = ivar_getName(ivs[i]);
        if (!in || strcmp(in, name) != 0) continue;
        off = ivar_getOffset(ivs[i]);
        if (typeOut) *typeOut = ivar_getTypeEncoding(ivs[i]);
        break;
    }
    if (ivs) free(ivs);
    return off;
}

// =====================================================================
// 对外: 侦查(只读) — 找类/实例/字段现值, 写日志
// =====================================================================
NSDictionary *mfInstProbe(const char *clsSub, const char *ivarName, size_t budgetMB) {
    Class c = mfiFindClass(clsSub);
    if (!c) { mfLog(@"[inst] 类未找到: %s", clsSub); return nil; }
    const char *cn = class_getName(c);
    const char *ty = NULL;
    ptrdiff_t off = mfiIvarOff(c, ivarName, &ty);
    mfLog(@"[inst] 类=%s ivar=%s off=%ld type=%s", cn, ivarName, (long)off, ty ?: "?");

    uintptr_t found[MFI_MAX_INST];
    size_t budget = budgetMB * 1024 * 1024;
    int n = mfiScan((uintptr_t)c, found, MFI_MAX_INST, budget);
    mfLog(@"[inst] 扫描完成: 实例=%d (预算 %zuMB)", n, budgetMB);

    NSMutableArray *vals = [NSMutableArray array];
    for (int i = 0; i < n && i < 8; i++) {
        uint8_t b = 0;
        if (off >= 0 && mfiRd(found[i] + (uintptr_t)off, &b, 1))
            [vals addObject:@(b)];
        mfLog(@"[inst]   #%d @%#lx  %s=%u", i, (unsigned long)found[i], ivarName, (unsigned)b);
    }
    return @{@"cls": @(cn), @"count": @(n), @"off": @(off), @"vals": vals};
}

// =====================================================================
// 对外: 写 — 把实例的 bool 字段置 1 (先读回验证)
// =====================================================================
int mfInstForceBool(const char *clsSub, const char *ivarName, size_t budgetMB) {
    Class c = mfiFindClass(clsSub);
    if (!c) { mfLog(@"[inst] 写: 类未找到 %s", clsSub); return -1; }
    ptrdiff_t off = mfiIvarOff(c, ivarName, NULL);
    if (off < 0) { mfLog(@"[inst] 写: ivar %s 未找到", ivarName); return -1; }

    uintptr_t found[MFI_MAX_INST];
    int n = mfiScan((uintptr_t)c, found, MFI_MAX_INST, budgetMB * 1024 * 1024);
    if (!n) { mfLog(@"[inst] 写: 未找到实例"); return 0; }

    int ok = 0;
    for (int i = 0; i < n; i++) {
        uintptr_t a = found[i] + (uintptr_t)off;
        uint8_t old = 0;
        if (!mfiRd(a, &old, 1)) continue;
        if (old == 1) { ok++; continue; }               // 已是解锁态
        uint8_t one = 1;
        if (!mfiWr(a, &one, 1)) { mfLog(@"[inst]   #%d 写失败 @%#lx", i, (unsigned long)a); continue; }
        uint8_t back = 0;
        BOOL land = mfiRd(a, &back, 1) && back == 1;
        mfLog(@"[inst]   #%d @%#lx %s: %u→%u %@", i, (unsigned long)a, ivarName,
              (unsigned)old, (unsigned)back, land ? @"✓已写入" : @"✗写后读回不符");
        if (land) ok++;
    }
    mfLog(@"[inst] 写完成: %d/%d 实例已置 %s=1", ok, n, ivarName);
    return ok;
}

// 便利: 对 HMVipProManager._isVipPro 做一次侦查+写 (通用化: 名字来自参数, 不硬编码 app)
void mfInstVipRun(BOOL doWrite) {
    size_t mb = 256;
    if (doWrite) {
        int ok = mfInstForceBool("VipProManager", "_isVipPro", mb);
        mfLog(@"[inst] _isVipPro 直写结果 ok=%d", ok);
    } else {
        mfInstProbe("VipProManager", "_isVipPro", mb);
    }
}
