// MFProcCapture.m — 第二拳·点位采集器 (被动, 零 hook)
// 层1 内存差分: ctor 快照主二进制 __TEXT/__DATA_CONST/__DATA, 2s diff — 抓直接写内存的 patch
// 层2 ObjC imp 巡检: 枚举全部类方法表, imp 落在 ReflixPatch dylib 镜像内 = 它 swizzle 的点
//     (实测教训: dylib 不写主二进制段 — 它是 NSInvocation+method_getImplementation 型 swizzle,
//      目标 selector 运行时解密, 但 objc 运行时表是明文, 类名/selector 直出)
// 产出: mfcap_*.json + hostlog 每事件一行

#import "MFPanel.h"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <string.h>
#import <os/object.h>
#import <os/lock.h>
#import <mach/mach.h>
#import <mach/exception.h>
#import <pthread.h>


#import "fishhook.h"

static NSString *mfCapHex(const uint8_t *p, size_t n);

// ===== 层5: 主二进制 mach_msg 观察 — app=license 客户端(六个子系统 id 全在主二进制, 2.29.1 实测) =====
// 只重绑 main image 的 mach_msg 导入(vendor dylib 自身调用不受影响, 绕开 backtrace 反 hook)
// MIG send+rcv 一体: 同次调用 rcv 缓冲区 = 服务端应答 → 一次 hook 抓全双向握手
static mach_msg_return_t (*g_origMachMsg)(mach_msg_header_t *, mach_msg_option_t, mach_msg_size_t,
                                          mach_msg_header_t *, mach_msg_size_t, mach_port_t, mach_msg_timeout_t);
static os_unfair_lock g_machLock = OS_UNFAIR_LOCK_INIT;
static int g_machCapCount = 0;

static inline BOOL mf_licReqId(uint32_t id) { return id == 0x965 || id == 0x966 || id == 0x967; }
static inline BOOL mf_licRepId(uint32_t id) { return id == 0x9c9 || id == 0x9ca || id == 0x9cb; }

static void mf_machDump(const char *kind, int seq, mach_msg_header_t *h) {
    if (!h) return;
    uint32_t size = h->msgh_size;
    if (size > 5276 || size < 24) return;
    @try {
        NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MinisFix"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSMutableString *body = [NSMutableString string];
        const uint8_t *b = (const uint8_t *)h;
        for (uint32_t i = 0; i < MIN(size, 512u); i++)
            [body appendFormat:@"%02x", b[i]];
        NSDictionary *r = @{@"kind": [NSString stringWithUTF8String:kind],
                            @"id": [NSString stringWithFormat:@"0x%x", h->msgh_id],
                            @"bits": [NSString stringWithFormat:@"0x%x", h->msgh_bits],
                            @"size": @(size),
                            @"retcode_0x20": size > 0x24 ? [NSString stringWithFormat:@"0x%08x",
                                *(const uint32_t *)(b + 0x20)] : @"n/a",
                            @"hex": body};
        NSString *path = [NSString stringWithFormat:@"%@/mfcap_mach_%s_%d_0x%x.json", dir, kind, seq, h->msgh_id];
        NSData *d = [NSJSONSerialization dataWithJSONObject:r options:NSJSONWritingPrettyPrinted error:nil];
        if (d) [d writeToFile:path atomically:YES];
        // hostlog 摘要: 前 48 字节
        NSString *head = [body substringToIndex:MIN(96, body.length)];
        mfLog(@"[capture] MACH%s #%d id=0x%x size=%u rc@0x20=%s hex=%@",
              kind, seq, h->msgh_id, size,
              (size > 0x24 ? [[NSString stringWithFormat:@"0x%08x", *(const uint32_t *)(b + 0x20)] UTF8String] : "n/a"),
              head);
    } @catch (NSException *e) {}
}

static void mf_machMaybeCap(mach_msg_header_t *send, mach_msg_header_t *rcv, mach_msg_return_t kr) {
    if (g_machCapCount >= 32) return;
    if (!send || !(send->msgh_bits & MACH_SEND_MSG)) return;
    if (!mf_licReqId(send->msgh_id)) return;
    os_unfair_lock_lock(&g_machLock);
    int seq = ++g_machCapCount;
    os_unfair_lock_unlock(&g_machLock);
    mf_machDump("REQ", seq, send);
    // rcv 缓冲区 = 同次调用收到的应答(MIG 风格 send+rcv)
    if ((kr == MACH_MSG_SUCCESS || kr == 0) && rcv && mf_licRepId(rcv->msgh_id))
        mf_machDump("REP", seq, rcv);
    else if (rcv && rcv->msgh_id)
        mfLog(@"[capture] MACHREQ #%d kr=0x%x rcv_id=0x%x (non-lic)", seq, kr, rcv->msgh_id);
    else
        mfLog(@"[capture] MACHREQ #%d id=0x%x kr=0x%x (no reply captured)", seq, send->msgh_id, kr);
}

static os_unfair_lock g_idLock = OS_UNFAIR_LOCK_INIT;
static uint32_t g_idSeen[64];
static uint32_t g_idCount = 0;
static void mf_machIdSeen(uint32_t id, uint32_t size) {
    os_unfair_lock_lock(&g_idLock);
    for (uint32_t i = 0; i < g_idCount; i++) if (g_idSeen[i] == id) { os_unfair_lock_unlock(&g_idLock); return; }
    if (g_idCount < 64) {
        g_idSeen[g_idCount++] = id;
        os_unfair_lock_unlock(&g_idLock);
        mfLog(@"[capture] MACHID id=0x%x size=%u (first seen)", id, size);
    } else os_unfair_lock_unlock(&g_idLock);
}
// v2.38.2: thread_get_state 链式捕获 — 拦截器(0x2a0a0)的 Q/A 黑匣子
kern_return_t thread_get_state(thread_act_t, thread_state_flavor_t, thread_state_t, mach_msg_type_number_t *);
static kern_return_t (*g_origTgs)(thread_act_t, thread_state_flavor_t, thread_state_t, mach_msg_type_number_t *);
static os_unfair_lock g_tgsLock = OS_UNFAIR_LOCK_INIT;
static uint32_t g_tgsCount = 0;
static kern_return_t mf_tgsHook(thread_act_t thread, thread_state_flavor_t flavor,
                                thread_state_t st, mach_msg_type_number_t *cnt) {
    kern_return_t kr = g_origTgs(thread, flavor, st, cnt);
    if (g_tgsCount < 32) {
        os_unfair_lock_lock(&g_tgsLock);
        if (g_tgsCount < 32) {
            uint32_t sz = st && cnt ? (*cnt * 4) : 0;
            if (sz > 3400) sz = 3400;
            uint8_t *buf = (uint8_t *)st;
            if (buf && sz) {
                char hx[2 * 3400 + 2];
                static const char *H = "0123456789abcdef";
                for (uint32_t j = 0; j < sz; j++) { hx[2*j] = H[buf[j] >> 4]; hx[2*j+1] = H[buf[j] & 15]; }
                hx[2*sz] = 0;
                mfLog(@"[capture] TGS#%u th=%p flavor=%u cnt=%u kr=%d state=%s",
                      g_tgsCount, (void *)thread, flavor, cnt ? *cnt : 0, kr, hx);
            } else {
                mfLog(@"[capture] TGS#%u th=%p flavor=%u cnt=null kr=%d (no buf)", g_tgsCount, (void *)thread, flavor, kr);
            }
            g_tgsCount++;
        }
        os_unfair_lock_unlock(&g_tgsLock);
    }
    return kr;
}
static uint8_t *mhCapMainText = NULL;   // v2.39.10: 主 __TEXT 运行时基址(ctor 记录)
static mach_port_t g_mitmVendorPort = MACH_PORT_NULL;
mach_port_t g_mitmMyPort = MACH_PORT_NULL;   // v2.47.3: 自家端口(非 static, MFRecon 侦查卡自证剔除要 extern)
static exception_behavior_t g_mitmOldBeh = 0;    // v2.44.0: swap 时捕获 vendor 原注册行为
static thread_state_flavor_t g_mitmOldFlv = 0;
static os_unfair_lock g_mitmLock = OS_UNFAIR_LOCK_INIT;
static uint32_t g_mitmCount = 0;
static void *mf_mitmServer(void *arg);
static void mfCapInstallTgsChain(struct mach_header_64 *mh, intptr_t slide) {
    if (g_origTgs) return;
    struct rebinding rb = {"thread_get_state", (void *)mf_tgsHook, (void **)&g_origTgs};
    int r = rebind_symbols_image((void *)mh, slide, &rb, 1);
    mfLog(@"[capture] TGS chain armed: rebind=%d hook=%p (t+3s, slot→0x2a0a0 已稳定)", r, g_origTgs);
    // v2.38.4: 异常端口侦查 — dylib vDLSYM task_set_exception_ports/thread_set_state + mach_msg_server
    //   异常端口通道: dylib 注册自己为 app 异常处理器, app 触发异常 → 内核直投(绕开一切 GOT/mach_msg 导入)
    //   → dylib 在 handler 里 thread_set_state 写寄存器交答案。若 task 异常端口非空 = 实锤。
    {
        exception_mask_t masks[32];
        mach_msg_type_number_t mCnt = 32;
        mach_port_t ports[32];
        exception_behavior_t behs[32];
        thread_state_flavor_t flvs[32];
        kern_return_t krx = task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, masks, &mCnt,
                                                     ports, behs, flvs);
        if (krx == KERN_SUCCESS && mCnt > 0) {
            for (uint32_t j = 0; j < mCnt && j < 32; j++)
                mfLog(@"[capture] EXCPORTS[%u] mask=0x%x port=0x%x beh=%d flv=%d",
                      j, masks[j], ports[j], behs[j], flvs[j]);
        } else {
            mfLog(@"[capture] EXCPORTS none (kr=%d cnt=%u)", krx, mCnt);
        }
    }
    // v2.40.0: 采样应答器(透明单发) — 守 BREAKPOINT 端口, 异常来了本地仿真原指令(基线快照有原字节),
    //   PC+=4(★ 4 连崩真因: 此前应答从不推进 PC), 答完即还 vendor 端口。门控 mfExcProbe 默认 ON(透明+单发+即还=安全)
    if ([[NSUserDefaults standardUserDefaults] boolForKey:@"mfExcProbeOff"]) return;   // 默认 ON, mfExcProbeOff=1 关
    // v2.39.4: 终局 MITM — swap EXC_BREAKPOINT 处理器到自己, 录 Q/A 后转发 vendor
    //   ★ 2.39.3 翻案: mask=0x40 = 1<<6 = EXC_BREAKPOINT(不是 EXC_SYSCALL!)
    //   ★ 2.39.7 终判: 手搓 MIG 转发 4 连崩(2406/2506/规范尺寸/穿透全试) — 协议录制路线 dead end
    //   替代品转向客户端侧逆向: 主二进制 wrapper(0x11d527c→brk 0x14211bc) 反汇编出答案消费逻辑, 本地造答案
    //   app 查询 = brk #0x965/0x966/0x967/0x9c9/0x9ca/0x9cb(立即数=请求码, v2.29.1 六个数=BRK imm)
    //   → EXC_BREAKPOINT(6) → 内核 mach_exception_raise_state(code=EXC_ARM_BREAKPOINT|imm<<16) 直投 vendor
    {
        mach_port_t self_ = mach_task_self();
        mach_port_t myPort = MACH_PORT_NULL;
        kern_return_t km = mach_port_allocate(self_, MACH_PORT_RIGHT_RECEIVE, &myPort);
        if (km == KERN_SUCCESS) {
            km = mach_port_insert_right(self_, myPort, myPort, MACH_MSG_TYPE_MAKE_SEND);
            mach_port_t oldPorts[32];
            exception_mask_t oldMasks[32];
            exception_behavior_t oldBehs[32];
            thread_state_flavor_t oldFlvs[32];
            mach_msg_type_number_t oldCnt = 32;
            kern_return_t ks = task_swap_exception_ports(self_, EXC_MASK_BREAKPOINT, myPort,
                    MACH_EXCEPTION_CODES | EXCEPTION_STATE, ARM_THREAD_STATE64,
                    oldMasks, &oldCnt, oldPorts, oldBehs, oldFlvs);
            if (ks == KERN_SUCCESS) {
                g_mitmVendorPort = MACH_PORT_NULL;
                for (uint32_t j = 0; j < oldCnt && j < 32; j++) {
                    if (oldMasks[j] & EXC_MASK_BREAKPOINT) {
                        g_mitmVendorPort = oldPorts[j];   // vendor 端口 send right 落到我们手里
                        g_mitmOldBeh = oldBehs[j];        // ★ 原注册行为(restore 必须原样, 否则真实 brk 格式错位→vendor 拒答→悬空)
                        g_mitmOldFlv = oldFlvs[j];
                        mfLog(@"[capture] MITM swap ok: old[%u] mask=0x%x vendor_port=0x%x beh=%d flv=%d",
                              j, oldMasks[j], oldPorts[j], oldBehs[j], oldFlvs[j]);
                    }
                }
                g_mitmMyPort = myPort;
                mfLog(@"[capture] MITM armed: myPort=0x%x vendor=0x%x km=%d ks=%d",
                      myPort, g_mitmVendorPort, km, ks);
                pthread_t thr;
                pthread_create(&thr, NULL, mf_mitmServer, (void *)(uintptr_t)myPort);
                pthread_detach(thr);   // v2.45.0: 无条件启动(真品退役后 vendor=0, 替代件独立守端口)
            } else {
                mfLog(@"[capture] MITM swap FAIL ks=%d myPort=0x%x", ks, myPort);
            }
        } else {
            mfLog(@"[capture] MITM alloc FAIL km=%d", km);
        }
    }
}

// v2.39.2: 手搓 64 位 MIG 异常交换(iOS SDK 无 mach_exc 头/导出, 布局照 xnu MIG, 4B pack)
#pragma pack(4)
typedef struct { mach_port_t name; mach_msg_size_t pad1; uint16_t pad2; uint8_t disp; uint8_t type; } mfPortDesc_t;
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t body;
    mfPortDesc_t thread;
    mfPortDesc_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
    int flavor;
    mach_msg_type_number_t old_stateCnt;
    uint32_t old_state[680];
} mfExcReq_t;
typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    int flavor;
    mach_msg_type_number_t new_stateCnt;
    uint32_t new_state[680];
} mfExcRep_t;
#pragma pack()
static uint8_t *mfCapSeg0Baseline(uint64_t *outSize);   // v2.40.1: __TEXT 基线快照访问(定义在 g_capSegs 后)
static void *mf_mitmServer(void *arg) {
    mach_port_t rcv = (mach_port_t)(uintptr_t)arg;
    mfLog(@"[capture] EXCPROBE up rcv=0x%x vendor=0x%x", rcv, g_mitmVendorPort);
    static uint8_t rbuf[8192] __attribute__((aligned(8)));
    for (;;) {
    kern_return_t kr = mach_msg((mach_msg_header_t *)rbuf, MACH_RCV_MSG | MACH_RCV_LARGE,
                                0, sizeof(rbuf), rcv, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) { mfLog(@"[capture] EXCPROBE rcv kr=%d", kr); return NULL; }
    mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
    mfLog(@"[capture] EXCMSG id=%u bits=%#x remote=%#x local=%#x size=%u", h->msgh_id, h->msgh_bits,
          h->msgh_remote_port, h->msgh_local_port, h->msgh_size);
    // 消息头 hex dump(前 96B) — 字段偏移离线校准
    {
        uint8_t *rb = (uint8_t *)rbuf;
        char hx[193];
        static const char *H = "0123456789abcdef";
        uint32_t nb = h->msgh_size < 96 ? h->msgh_size : 96;
        for (uint32_t j = 0; j < nb; j++) { hx[2*j] = H[rb[j] >> 4]; hx[2*j+1] = H[rb[j] & 15]; }
        hx[2*nb] = 0;
        mfLog(@"[capture] EXCDATA %s", hx);   // char 数组直接 %s(@(hx)=对象指针是乱码根源)
    }
    if (h->msgh_id != 2405 && h->msgh_id != 2406) {
        mfExcRep_t nf;
        memset(&nf, 0, sizeof(nf));
        nf.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        nf.Head.msgh_size = 36;
        nf.Head.msgh_remote_port = h->msgh_remote_port;   // 回复权在 remote(实测 bits=0x1112)
        nf.Head.msgh_id = h->msgh_id + 100;
        nf.NDR = NDR_record;
        nf.RetCode = KERN_FAILURE;
        kern_return_t knf = mach_msg(&nf.Head, MACH_SEND_MSG, 36, 0, MACH_PORT_NULL,
                                     MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        mfLog(@"[capture] EXCPROBE skip id=%u reply kr=%d", h->msgh_id, knf);
        continue;
    }
    // ★ 机制终案: 这不是内核异常 — 是 app 自造的 2406 MIG 请求(简单消息无 COMPLEX 位,
    //   线程端口内联非描述符, thread_get_state 必败), state 内联在消息里:
    //   w14=flavor(6) w15=cnt(0x44) w16..w83=68 词寄存器现场(pc=w[48])
    uint32_t *mw = (uint32_t *)rbuf;
    uint32_t nWords = h->msgh_size / 4;
    uint32_t flavor = (nWords > 14) ? mw[14] : 0;
    uint32_t cnt = (nWords > 15) ? mw[15] : 0;
    mfLog(@"[capture] EXCPARSE flavor=%u cnt=%u w8=%u w10=%u w12=%#x w13=%u", flavor, cnt, mw[8], mw[10], mw[12], mw[13]);
    uint64_t st[68];
    memset(st, 0, sizeof(st));
    if (cnt == 68 && nWords >= 84) {
        for (int k = 0; k < 68; k++) st[k] = mw[16 + k] | ((uint64_t)mw[17 + 2*k] << 32);
        // 上面步长错了 — 正确: u32 数组两两拼 u64
        for (int k = 0; k < 68; k++) st[k] = (uint64_t)mw[16 + 2*k] | ((uint64_t)mw[17 + 2*k] << 32);
        // 状态 hex 全量(两行)
        static char hx[2 * 68 * 4 + 2];   // 68 u64 × 16 hex + NUL(2.41.2 写成 138B → 栈溢出)
        static const char *H = "0123456789abcdef";
        for (int k = 0; k < 68; k++) {
            uint64_t v = st[k];
            for (int b = 0; b < 16; b++)
                hx[16*k + b] = H[(v >> (60 - 4*b)) & 15];
        }
        hx[16*68] = 0;
        mfLog(@"[capture] EXCSTATE %s", hx);
    }
    uint64_t pc = st[32];
    uint64_t site = (mhCapMainText && pc > (uint64_t)(uintptr_t)mhCapMainText && pc - (uint64_t)(uintptr_t)mhCapMainText < 0x2e30000)
                    ? pc - (uint64_t)(uintptr_t)mhCapMainText : 0;
    uint32_t liveInsn = 0, origInsn = 0;
    if (pc) vm_read_overwrite(mach_task_self(), (vm_address_t)pc, 4, (vm_address_t)&liveInsn, &(vm_size_t){4});
    if (site && site + 4 <= 0x2e30000) {
        uint64_t sz0 = 0;
        uint8_t *b0 = mfCapSeg0Baseline(&sz0);
        if (b0 && site + 4 <= sz0) memcpy(&origInsn, b0 + site, 4);
    }
    uint32_t imm = ((liveInsn & 0xFFE0001F) == 0xD4200000) ? ((liveInsn >> 5) & 0xFFFF) : 0;
    mfLog(@"[capture] EXCSITE id=%#llx main+0x%llx live=%08x(orig=%08x) brk_imm=%#x",
          (unsigned long long)((nWords > 12) ? mw[12] : 0),
          (unsigned long long)site, liveInsn, origInsn, imm);
    mfLog(@"[capture] EXCREGS x0=%llx x1=%llx x2=%llx x3=%llx x8=%llx x9=%llx x16=%llx x29=%llx pc=%llx",
          (unsigned long long)st[0], (unsigned long long)st[1], (unsigned long long)st[2],
          (unsigned long long)st[3], (unsigned long long)st[8], (unsigned long long)st[9],
          (unsigned long long)st[16], (unsigned long long)st[29], (unsigned long long)pc);
    // 透明仿真原指令(LDUR/STUR 64b imm9)
    uint64_t ns[68];
    memcpy(ns, st, sizeof(ns));
    int emulated = 0;
    if ((origInsn & 0xFFE00C00) == 0xF8400000 || (origInsn & 0xFFE00C00) == 0xF8000000) {   // LDUR64=0xF840..., STUR64=0xF800...(2.43 掩码错)
        int64_t simm = (int64_t)((origInsn >> 12) & 0x1FF); if (simm & 0x100) simm -= 0x200;
        uint32_t Rn = (origInsn >> 5) & 0x1F, Rt = origInsn & 0x1F;
        uint64_t base = ns[Rn];
        if ((origInsn >> 22) & 1) {
            uint64_t v = 0;
            vm_read_overwrite(mach_task_self(), (vm_address_t)(base + simm), 8, (vm_address_t)&v, &(vm_size_t){8});
            ns[Rt] = v;
            mfLog(@"[capture] EXCEMU ldur x%u,[x%u,%#llx] = %#llx", Rt, Rn, (unsigned long long)simm, (unsigned long long)v);
        } else {
            uint64_t v = ns[Rt];
            vm_write(mach_task_self(), (vm_address_t)(base + simm), (vm_offset_t)&v, 8);
            mfLog(@"[capture] EXCEMU stur x%u,[x%u,%#llx] <- %#llx", Rt, Rn, (unsigned long long)simm, (unsigned long long)v);
        }
        emulated = 1;
    } else if (origInsn) {
        mfLog(@"[capture] EXCEMU unsupported orig=%08x (passthrough)", origInsn);
    } else {
        mfLog(@"[capture] EXCEMU no site (passthrough)");
    }
    ns[32] = pc + 4;   // ★ 推 PC 越过 brk/查询点
    // 伪造值钩子: mfExcFakeX9 >= 0 覆盖 x9(枚举器)
    double fake = -1;
    id fakeObj = [[NSUserDefaults standardUserDefaults] objectForKey:@"mfExcFakeX9"];
    if (fakeObj) fake = [fakeObj doubleValue];
    if (fake >= 0) {
        ns[9] = (uint64_t)fake;
        mfLog(@"[capture] EXCFAKE x9 <- %#llx", (unsigned long long)(uint64_t)fake);
    }
    // v2.43.0: 三模式 — mfExcProxy: 2=替代应答(回显+判定), 1=转发录制(vendor 在场), 0=纯观察
    uint64_t qaNonce = st[1];
    NSInteger proxyMode = 2;   // 默认=替代应答(vendor 出局)
    id pmObj = [[NSUserDefaults standardUserDefaults] objectForKey:@"mfExcProxy"];
    if (pmObj) proxyMode = [pmObj integerValue];   // 1=转发录制, 0=观察
    if (proxyMode == 2) {
        // ★ 替代件: 回显 nonce + x9=1(通过) + x4 自增 + pc+=4, 不需要 vendor
        //   (从三组 Q/A 实测归纳: x1/x15=nonce 回显, x0/x16=app 缓冲原样, x9=1=通过)
        uint64_t cnt4 = ns[4] + 1;
        memcpy(ns, st, sizeof(ns));       // 现场原样(含 x0/x16 指针回显)
        ns[1] = st[1];                    // nonce 回显
        ns[15] = st[1];                   // x15 同 nonce
        ns[4] = cnt4;                     // 查询计数
        ns[9] = 1;                        // ★ 判定位: 通过
        ns[32] = pc + 4;                  // 越过查询点
        mfLog(@"[capture] PROXY ans nonce=%#llx x4=%llu x9=1 pc=%llx->%llx",
              (unsigned long long)qaNonce, (unsigned long long)cnt4,
              (unsigned long long)pc, (unsigned long long)(pc + 4));
        emulated = 3;   // 3 = 替代模式
        goto reply_now;
    }
    // v2.42.0: 终局 — 转发 vendor 录 Q/A, app 无感
    //   app 自造 2406 (336B simple msg, bits=0x1112, x1=nonce) → 我们 → vendor(mach_msg_server) → 2506 → app
    //   转发 = 字节复制改两端口字段; audit token 同 task 天然一致
    uint64_t vendReply[68];
    int gotVend = 0;
    if (g_mitmVendorPort != MACH_PORT_NULL && h->msgh_size <= 4096) {
        mach_port_t frp = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &frp) == KERN_SUCCESS) {
            static uint8_t fbuf[4096] __attribute__((aligned(8)));
            memcpy(fbuf, rbuf, h->msgh_size);
            mach_msg_header_t *f = (mach_msg_header_t *)fbuf;
            f->msgh_remote_port = g_mitmVendorPort;
            f->msgh_local_port = frp;
            f->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
            f->msgh_voucher_port = MACH_PORT_NULL;
            f->msgh_id = h->msgh_id;
            kern_return_t kf = mach_msg(f, MACH_SEND_MSG | MACH_SEND_TIMEOUT, h->msgh_size, 0,
                                        MACH_PORT_NULL, 1000, MACH_PORT_NULL);
            mfLog(@"[capture] FWD send kr=%d to vendor=%#x", kf, g_mitmVendorPort);
            if (kf == KERN_SUCCESS) {
                static uint8_t vrep[8192] __attribute__((aligned(8)));
                kern_return_t kv = mach_msg((mach_msg_header_t *)vrep, MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT,
                                            0, sizeof(vrep), frp, 2000, MACH_PORT_NULL);
                mfLog(@"[capture] FWD rcv kr=%d id=%u size=%u", kv,
                      (kv == KERN_SUCCESS) ? ((mach_msg_header_t *)vrep)->msgh_id : 0,
                      (kv == KERN_SUCCESS) ? ((mach_msg_header_t *)vrep)->msgh_size : 0);
                if (kv == KERN_SUCCESS) {
                    mach_msg_header_t *vr = (mach_msg_header_t *)vrep;
                    uint32_t *vw = (uint32_t *)vrep;
                    // 2506 形状: Head24 NDR8 RetCode4 flavor4 cnt4 state[..]
                    if (vr->msgh_id == h->msgh_id + 100 && vr->msgh_size >= 44) {
                        kern_return_t vrc = vw[8];
                        uint32_t vflv = vw[9];    // 实测: flavor=0(vendor 自定义)
                        uint32_t vcnt = vw[10];   // 实测: 68 在 vw[10], state 从 vw[11] 起(2.42.1 差 4 字节)
                        mfLog(@"[capture] Q&A nonce=%llx RetCode=%d flv=%u cnt=%u",
                              (unsigned long long)qaNonce, vrc, vflv, vcnt);
                        if (vrc == KERN_SUCCESS && vcnt == 68 && vr->msgh_size >= 44 + 272) {
                            uint32_t *vst = vw + 11;
                            gotVend = 1;
                            memcpy(vendReply, vst, 272);
                            // 答案全量 hex (68 u64, 544 hex chars, 分两行)
                            static char ahx[2 * 68 * 4 + 2];
                            static const char *H = "0123456789abcdef";
                            for (int k = 0; k < 68; k++) {
                                uint64_t v = vst[2*k] | ((uint64_t)vst[2*k+1] << 32);
                                for (int b = 0; b < 16; b++)
                                    ahx[16*k + b] = H[(v >> (60 - 4*b)) & 15];
                            }
                            ahx[16*68] = 0;
                            mfLog(@"[capture] ANS1 %s", ahx);
                            mfLog(@"[capture] ANS2 %s", ahx + 272);
                            // 直接采用 vendor 答案
                            memcpy(ns, vendReply, sizeof(ns));
                            ns[32] = pc + 4;   // 保险: PC 越过查询点(vendor 或已推, 兜底)
                            emulated = 2;      // 2 = vendor 转发模式
                        }
                    } else {
                        mfLog(@"[capture] FWD unexpected reply id=%u", vr->msgh_id);
                    }
                }
            }
            mach_port_mod_refs(mach_task_self(), frp, MACH_PORT_RIGHT_RECEIVE, -1);
        }
    }
reply_now:
    // 应答: ★ MOVE_SEND_ONCE 到 remote(回复权在 remote), 316B MIG 2506 形状
    mfExcRep_t out;
    memset(&out, 0, sizeof(out));
    out.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    out.Head.msgh_size = (mach_msg_size_t)(44 + 4u * ARM_THREAD_STATE64_COUNT);
    out.Head.msgh_remote_port = h->msgh_remote_port;
    out.Head.msgh_id = h->msgh_id + 100;
    out.NDR = NDR_record;
    out.RetCode = KERN_SUCCESS;
    out.flavor = ARM_THREAD_STATE64;
    out.new_stateCnt = ARM_THREAD_STATE64_COUNT;
    memcpy(out.new_state, ns, sizeof(ns));
    mfLog(@"[capture] EXCPROBE replying size=%u to remote=%#x", out.Head.msgh_size, out.Head.msgh_remote_port);
    kr = mach_msg(&out.Head, MACH_SEND_MSG | MACH_SEND_TIMEOUT, out.Head.msgh_size, 0, MACH_PORT_NULL,
                  100, MACH_PORT_NULL);   // 100ms: send-once 无接收者则 TIMEOUT, 绝不挂线程
    mfLog(@"[capture] EXCPROBE reply kr=%d (%#x) emu=%d(0=pw,1=emu,2=vend) site=%#llx", kr, kr, emulated, (unsigned long long)site);
    if (kr != KERN_SUCCESS) {
        task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, g_mitmVendorPort,
                                 g_mitmOldBeh, g_mitmOldFlv);
        mfLog(@"[capture] EXCPROBE reply FAIL -> vendor restored (beh=%d)", g_mitmOldBeh);
    }
    // v2.45.0: proxy 模式 = 我们就是 license server, 不还端口; 转发/观察模式每条后还 vendor
    if (proxyMode != 2) {
        kern_return_t kr2 = task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, g_mitmVendorPort,
                                                     g_mitmOldBeh, g_mitmOldFlv);
        mfLog(@"[capture] EXCPROBE port restored kr=%d", kr2);
    }
    } // for
    return NULL;
}
// v2.38.4: mach_msg_send / mach_msg_overwrite — 被漏掉的 MIG 客户端面(主镜像 rebind)
static kern_return_t (*g_origMachMsgSend)(mach_msg_header_t *);
static uint32_t g_msendLog = 0;
static kern_return_t mf_machMsgSendHook(mach_msg_header_t *msg) {
    kern_return_t kr = g_origMachMsgSend(msg);
    if (msg && g_msendLog < 100) {
        g_msendLog++;
        mfLog(@"[capture] MSEND id=0x%x size=%u to=0x%x remote=0x%x kr=%d",
              msg->msgh_id, msg->msgh_size, msg->msgh_remote_port, msg->msgh_remote_port, kr);
    }
    return kr;
}
static kern_return_t (*g_origMachMsgOverwrite)(mach_msg_header_t *, mach_msg_option_t, mach_msg_size_t,
                                               mach_msg_header_t *, mach_msg_size_t, mach_port_t, mach_msg_timeout_t);
static uint32_t g_moverLog = 0;
static kern_return_t mf_machMsgOverwriteHook(mach_msg_header_t *msg, mach_msg_option_t option,
                                             mach_msg_size_t send_size, mach_msg_header_t *rcv_msg,
                                             mach_msg_size_t rcv_limit, mach_port_t notify,
                                             mach_msg_timeout_t timeout) {
    kern_return_t kr = g_origMachMsgOverwrite(msg, option, send_size, rcv_msg, rcv_limit, notify, timeout);
    if (msg && (msg->msgh_bits & MACH_SEND_MSG) && g_moverLog < 100) {
        g_moverLog++;
        mfLog(@"[capture] MOVER id=0x%x size=%u to=0x%x kr=%d", msg->msgh_id, send_size, msg->msgh_remote_port, kr);
    }
    return kr;
}
static mach_msg_return_t mf_machMsgHook(mach_msg_header_t *msg, mach_msg_option_t option,
        mach_msg_size_t send_size, mach_msg_header_t *rcv_msg, mach_msg_size_t rcv_limit,
        mach_port_t notify, mach_msg_timeout_t timeout) {
    mach_msg_return_t kr = g_origMachMsg(msg, option, send_size, rcv_msg, rcv_limit, notify, timeout);
    if (msg && (msg->msgh_bits & MACH_SEND_MSG) && msg->msgh_id) mf_machIdSeen(msg->msgh_id, send_size);
    mf_machMaybeCap(msg, rcv_msg, kr);
    return kr;
}

static void mfCapInstallMachTap(const struct mach_header_64 *mh, intptr_t slide) {
    if (g_origMachMsg) return;
    struct rebinding rb = {"mach_msg", (void *)mf_machMsgHook, (void **)&g_origMachMsg};
    int r = rebind_symbols_image((void *)mh, slide, &rb, 1);
    mfLog(@"[capture] main-image mach_msg rebind: %d (hook=%p)", r, g_origMachMsg);
}

// v2.32.0: mach_msg2 — iOS 16+ 新 ABI, 独立符号(v2.31.0 实测主二进制 mach_msg 零流量后的补网)
static mach_msg_return_t (*g_origMachMsg2)(mach_msg_header_t *, mach_msg_option_t, mach_msg_size_t,
                                           mach_msg_header_t *, mach_msg_size_t, mach_port_t, mach_msg_timeout_t);
static mach_msg_return_t mf_machMsg2Hook(mach_msg_header_t *msg, mach_msg_option_t option,
        mach_msg_size_t send_size, mach_msg_header_t *rcv_msg, mach_msg_size_t rcv_limit,
        mach_port_t notify, mach_msg_timeout_t timeout) {
    mach_msg_return_t kr = g_origMachMsg2(msg, option, send_size, rcv_msg, rcv_limit, notify, timeout);
    if (msg && (msg->msgh_bits & MACH_SEND_MSG) && msg->msgh_id) mf_machIdSeen(msg->msgh_id, send_size);
    if (msg && (msg->msgh_bits & MACH_SEND_MSG) && mf_licReqId(msg->msgh_id) && g_machCapCount < 32) {
        os_unfair_lock_lock(&g_machLock);
        int seq = ++g_machCapCount;
        os_unfair_lock_unlock(&g_machLock);
        mf_machDump("REQ2", seq, msg);
        if (rcv_msg && (kr == MACH_MSG_SUCCESS || kr == 0)) mf_machDump("REP2", seq, rcv_msg);
        else mfLog(@"[capture] MACH2REQ #%d id=0x%x kr=0x%x (no reply)", seq, msg->msgh_id, kr);
    }
    return kr;
}

// ===== 层7: vendor dylib 自身 syscall 窃听 — 服务端循环/页权限/动态加载全上报 =====
// 它导入 40 符号: mach_msg_server 起服务线程, vm_protect 解锁 main __TEXT 尾(0x2c8c000 v2.20 实录),
// dlopen/dlsym 动态加载, NSClassFromString/NSSelectorFromString 动态调任意 API。
// 客户端消息最终都会抵达服务端 — 从 dylib 侧的 mach_msg 抓, 一张网兜住全部收发。
extern uint8_t *g_capDylibBase;    // 定义在层2 段(下方), 前向引用
extern uint64_t g_capDylibSize;

// ===== v2.33.0: objc_msgSend 蹦床(arm64) — 保 x0-x8/x16/lr 实参, 日志后尾跳原函数 =====
extern void mf_msgSendTramp(void);
void *g_vOrigMsgSendPtr = NULL;
__asm__(
  ".text\n"
  ".align 2\n"
  "_mf_msgSendTramp:\n"
  "  stp x29, x30, [sp, #-16]!\n"
  "  sub sp, sp, #80\n"
  "  stp x0, x1, [sp]\n"
  "  stp x2, x3, [sp, #16]\n"
  "  stp x4, x5, [sp, #32]\n"
  "  stp x6, x7, [sp, #48]\n"
  "  stp x8, x16, [sp, #64]\n"
  "  bl _mf_msgSendLogger\n"
  "  ldp x0, x1, [sp]\n"
  "  ldp x2, x3, [sp, #16]\n"
  "  ldp x4, x5, [sp, #32]\n"
  "  ldp x6, x7, [sp, #48]\n"
  "  ldp x8, x16, [sp, #64]\n"
  "  add sp, sp, #80\n"
  "  ldp x29, x30, [sp], #16\n"
  "  adrp x16, _g_vOrigMsgSendPtr@PAGE\n"
  "  ldr x16, [x16, _g_vOrigMsgSendPtr@PAGEOFF]\n"
  "  br x16\n"
);
// 只有 dylib 镜像的 msgSend 会进蹦床(IAPtools 自己的调用不在重绑范围, 无递归)
// v2.35.0: logger 加 x2 实参 — performSelector: 的目标 selector / isEqualToString: 的比较串
//   (蹦床里 x2 未被破坏, 直接作第三参; 这些参数就是 MBA 解密后的明文)
void mf_msgSendLogger(id rcv, SEL sel, void *a0) {
    static NSMutableDictionary *seen = nil;
    static os_unfair_lock lk = OS_UNFAIR_LOCK_INIT;
    static uint32_t cnt = 0;
    if (!rcv || cnt >= 120) return;
    Class c = object_getClass(rcv);
    if (!c) return;
    const char *cn = class_getName(c);
    const char *sn = sel ? sel_getName(sel) : "?";
    NSString *extra = @"";
    if (sel && !strcmp(sn, "performSelector:") && (uintptr_t)a0 >= 0x1000) {
        extra = [NSString stringWithFormat:@" (arg=%s)", sel_getName((SEL)a0)];
    } else if (sel && !strcmp(sn, "setSelector:") && (uintptr_t)a0 >= 0x1000) {
        // v2.36.1: NSInvocation setSelector: 的实参 = 真正被调用的 selector(解锁调用名)
        extra = [NSString stringWithFormat:@" (SEL=%s)", sel_getName((SEL)a0)];
    } else if (sel && !strcmp(sn, "setTarget:") && (uintptr_t)a0 >= 0x1000) {
        // v2.36.1: setTarget: 实参 = 解锁调用的目标对象(类名)
        @try {
            id t = (__bridge id)a0;
            const char *n = object_isClass(t) ? class_getName((Class)t)
                                              : class_getName(object_getClass(t));
            extra = [NSString stringWithFormat:@" (target=%s%s)", n,
                     object_isClass(t) ? " [CLASS]" : ""];
        } @catch (NSException *e) { extra = @" (target=?)"; }
    } else if (sel && (!strcmp(sn, "isEqualToString:") || !strcmp(sn, "hasPrefix:")) && a0) {
        @try {
            if ([(__bridge id)a0 isKindOfClass:[NSString class]]) {
                NSString *t = (__bridge NSString *)a0;
                if (t.length > 64) t = [t substringToIndex:64];
                extra = [NSString stringWithFormat:@" (arg=%@)", t];
            }
        } @catch (NSException *e) {}
    }
    os_unfair_lock_lock(&lk);
    if (!seen) seen = [NSMutableDictionary dictionary];
    NSString *k = [NSString stringWithFormat:@"%s|%s|%@", cn, sn, extra];
    BOOL dup = (seen[k] != nil);
    if (!dup) { seen[k] = @YES; cnt++; }
    os_unfair_lock_unlock(&lk);
    if (!dup) mfLog(@"[capture] MSGSEND %s -> %s%@", cn, sn, extra);
}

// ===== v2.33.0: 动态解析明文钩 — 它解密后的类名/selector 名在此现形 =====
static Class (*g_vOrigClsFromStr)(NSString *) = NULL;
static SEL (*g_vOrigSelFromStr)(NSString *) = NULL;
static IMP (*g_vOrigGetImp)(Method) = NULL;
static Method (*g_vOrigGetInstM)(Class, SEL) = NULL;

static Class mf_vClsFromStrHook(NSString *s) {
    Class c = g_vOrigClsFromStr(s);
    if (s.length && s.length < 100) mfLog(@"[capture] vCLS %@", s);
    return c;
}
static SEL mf_vSelFromStrHook(NSString *s) {
    SEL sel = g_vOrigSelFromStr(s);
    if (s.length && s.length < 100) mfLog(@"[capture] vSEL %@", s);
    return sel;
}
static IMP mf_vGetImpHook(Method m) {
    IMP imp = g_vOrigGetImp(m);
    if (m) {
        SEL s = method_getName(m);
        const char *sn = sel_getName(s);
        unsigned long off = 0; const char *zone = "ext";
        uintptr_t a = (uintptr_t)imp;
        if (g_capDylibBase && a >= (uintptr_t)g_capDylibBase && a < (uintptr_t)g_capDylibBase + g_capDylibSize) {
            zone = "dylib"; off = a - (uintptr_t)g_capDylibBase;
        } else if (a >= 0x100000000ULL && a < 0x103000000ULL) {
            zone = "main"; off = a - 0x100000000ULL;
        }
        mfLog(@"[capture] vGETIMP %s -> %s+0x%lx", sn, zone, off);
    }
    return imp;
}
static Method mf_vGetInstMHook(Class c, SEL s) {
    Method m = g_vOrigGetInstM(c, s);
    if (c && s) mfLog(@"[capture] vGETM %s -> %s", class_getName(c), sel_getName(s));
    return m;
}

static mach_msg_return_t (*g_vOrigMachMsg)(mach_msg_header_t *, mach_msg_option_t, mach_msg_size_t,
                                           mach_msg_header_t *, mach_msg_size_t, mach_port_t, mach_msg_timeout_t);
static kern_return_t (*g_vOrigVMProtect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
static void *(*g_vOrigDlopen)(const char *, int);
static void *(*g_vOrigDlsym)(void *, const char *);
static uint32_t g_vMachCount = 0;
static uint32_t g_vVMCount = 0;
static os_unfair_lock g_vLock = OS_UNFAIR_LOCK_INIT;

// v2.34.0: 瞬时补丁抓取 — 授权 RW 时拍 before, 收回写权限时拍 after, diff = 瞬时 patch 字节
typedef struct { vm_address_t addr; vm_size_t size; uint8_t *pre; int active; } mfVMPWatch;
static mfVMPWatch g_vmpWatch[8];
static void mf_vmpWatchReport(mfVMPWatch *w) {
    uint32_t changes = 0;
    @try {
        for (uint64_t i = 0; i < w->size;) {
            if (w->pre[i] == ((const uint8_t *)w->addr)[i]) { i++; continue; }
            uint64_t st = i;
            while (i < w->size && w->pre[i] != ((const uint8_t *)w->addr)[i]) i++;
            if (changes < 16) {
                mfLog(@"[capture] TRANSIENT @0x%llx+0x%llx len=%llu %s→%s",
                      (unsigned long long)w->addr + st, (unsigned long long)st,
                      (unsigned long long)(i - st),
                      mfCapHex(w->pre + st, 16), mfCapHex((const uint8_t *)w->addr + st, 16));
                @try {
                    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MinisFix"];
                    NSDictionary *r = @{@"addr":[NSString stringWithFormat:@"0x%llx", w->addr + st],
                                        @"len":@(i - st),
                                        @"before":mfCapHex(w->pre + st, 64),
                                        @"after":mfCapHex((const uint8_t *)w->addr + st, 64)};
                    NSData *d = [NSJSONSerialization dataWithJSONObject:r options:NSJSONWritingPrettyPrinted error:nil];
                    if (d) [d writeToFile:[NSString stringWithFormat:@"%@/mfcap_transient_%u_%llu.json",
                                dir, g_vVMCount, (unsigned long long)st] atomically:YES];
                } @catch (NSException *e) {}
            }
            changes++;
        }
    } @catch (NSException *e) {}
    mfLog(@"[capture] TRANSIENT-DONE %u regions changed", changes);
}
static kern_return_t mf_vVMProtectHook(vm_map_t map, vm_address_t addr, vm_size_t sz,
                                       boolean_t set_max, vm_prot_t prot) {
    // v2.36.1: 真实签名 5 参 — x4=set_maximum(bool), x5=new_prot(此前误把 bool 当 prot 打了 0)
    // 拍 before: 本 dylib 申请写权限且目标未在监视 → 快照
    if ((prot & VM_PROT_WRITE) && sz > 0 && sz <= (1<<20)) {
        int slot = -1;
        for (int i = 0; i < 8; i++) {
            if (g_vmpWatch[i].active && g_vmpWatch[i].addr == addr && g_vmpWatch[i].size == sz) { slot = -2; break; }
            if (!g_vmpWatch[i].active && slot < 0) slot = i;
        }
        if (slot >= 0) {
            uint8_t *pre = malloc((size_t)sz);
            if (pre) { memcpy(pre, (const void *)addr, (size_t)sz);
                       g_vmpWatch[slot] = (mfVMPWatch){addr, sz, pre, 1};
                       mfLog(@"[capture] VMPROT-WATCH armed 0x%llx size=0x%lx prot=%d (pre snapshot)",
                             (unsigned long long)addr, (unsigned long)sz, prot); }
        }
    }
    kern_return_t kr = g_vOrigVMProtect(map, addr, sz, set_max, prot);
    // 拍 after: 同区域收回写权限 → diff 上报
    if (!(prot & VM_PROT_WRITE)) {
        for (int i = 0; i < 8; i++) {
            if (g_vmpWatch[i].active && g_vmpWatch[i].addr == addr && g_vmpWatch[i].size == sz) {
                mf_vmpWatchReport(&g_vmpWatch[i]);
                free(g_vmpWatch[i].pre); g_vmpWatch[i] = (mfVMPWatch){0};
            }
        }
    }
    os_unfair_lock_lock(&g_vLock);
    uint32_t seq = ++g_vVMCount;
    os_unfair_lock_unlock(&g_vLock);
    if (seq <= 24 && sz <= (1<<20)) {
        // 目标在主二进制内? 换算镜像偏移(主 __TEXT vm 0x100000000 起)
        uintptr_t a = (uintptr_t)addr;
        const char *zone = "ext";
        unsigned long off = 0;
        if (g_capDylibBase && a >= (uintptr_t)g_capDylibBase && a < (uintptr_t)g_capDylibBase + g_capDylibSize) {
            zone = "dylib"; off = a - (uintptr_t)g_capDylibBase;
        } else if (a >= 0x100000000ULL && a < 0x103000000ULL) {
            zone = "main"; off = a - 0x100000000ULL;
        }
        mfLog(@"[capture] VMPROT #%u %s+0x%lx size=0x%lx prot=%d kr=%d (raw=0x%llx setmax=%d)",
              seq, zone, off, (unsigned long)sz, prot, kr,
              (unsigned long long)addr, set_max);
        if (zone == (const char *)"main") {
            @try {
                NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MinisFix"];
                NSDictionary *r = @{@"zone":@"main", @"addr":[NSString stringWithFormat:@"0x%lx", off],
                                    @"size":[NSString stringWithFormat:@"0x%lx", (unsigned long)sz],
                                    @"prot":@(prot), @"kr":@(kr), @"seq":@(seq)};
                NSData *d = [NSJSONSerialization dataWithJSONObject:r options:NSJSONWritingPrettyPrinted error:nil];
                if (d) [d writeToFile:[NSString stringWithFormat:@"%@/mfcap_vmprot_%u.json", dir, seq]
                            atomically:YES];
            } @catch (NSException *e) {}
        }
    }
    return kr;
}

static mach_msg_return_t mf_vMachMsgHook(mach_msg_header_t *msg, mach_msg_option_t option,
        mach_msg_size_t send_size, mach_msg_header_t *rcv_msg, mach_msg_size_t rcv_limit,
        mach_port_t notify, mach_msg_timeout_t timeout) {
    mach_msg_return_t kr = g_vOrigMachMsg(msg, option, send_size, rcv_msg, rcv_limit, notify, timeout);
    // 服务端视角: 收到的(req)和发出的(rep)都可能是 license 流量 — 全记, id 白名单外只记摘要
    os_unfair_lock_lock(&g_vLock);
    uint32_t seq = ++g_vMachCount;
    os_unfair_lock_unlock(&g_vLock);
    if (seq <= 48) {
        BOOL lic = msg && (mf_licReqId(msg->msgh_id) || mf_licRepId(msg->msgh_id));
        BOOL rcvLic = rcv_msg && (mf_licReqId(rcv_msg->msgh_id) || mf_licRepId(rcv_msg->msgh_id));
        if (lic || rcvLic) {
            if (msg && (option & MACH_SEND_MSG)) mf_machDump("vREQ", seq, msg);
            if (rcv_msg && (kr == MACH_MSG_SUCCESS || kr == 0)) mf_machDump("vREP", seq, rcv_msg);
        } else {
            uint32_t sid = msg ? msg->msgh_id : 0, rid = rcv_msg ? rcv_msg->msgh_id : 0;
            if (sid || rid) mfLog(@"[capture] vMACH #%u opt=0x%x send_id=0x%x rcv_id=0x%x kr=0x%x",
                                  seq, option, sid, rid, kr);
        }
    }
    return kr;
}

static void *mf_vDlopenHook(const char *path, int mode) {
    void *h = g_vOrigDlopen(path, mode);
    mfLog(@"[capture] vDLOPEN %s -> %p", path ?: "(null)", h);
    return h;
}
static void *mf_vDlsymHook(void *h, const char *name) {
    void *p = g_vOrigDlsym(h, name);
    mfLog(@"[capture] vDLSYM %s -> %p", name ?: "(null)", p);
    return p;
}

static void mfCapTapVendorDylib(void) {
    if (!g_capDylibBase || g_vOrigVMProtect) return;
    // dylib 镜像 slide: 段 vmaddr 从 0 起 → slide = 实际加载地址
    struct rebinding rbs[] = {
        {"vm_protect", (void *)mf_vVMProtectHook, (void **)&g_vOrigVMProtect},
        {"dlopen",     (void *)mf_vDlopenHook,    (void **)&g_vOrigDlopen},
        {"dlsym",      (void *)mf_vDlsymHook,     (void **)&g_vOrigDlsym},
        // v2.33.0: 动态调用面全收 — 它的 NSClassFromString/NSSelectorFromString 解密后的明文在这层直接现形
        {"NSClassFromString",     (void *)mf_vClsFromStrHook, (void **)&g_vOrigClsFromStr},
        {"NSSelectorFromString",  (void *)mf_vSelFromStrHook, (void **)&g_vOrigSelFromStr},
        {"method_getImplementation", (void *)mf_vGetImpHook,  (void **)&g_vOrigGetImp},
        {"class_getInstanceMethod",  (void *)mf_vGetInstMHook,(void **)&g_vOrigGetInstM},
        // 大杀器: objc_msgSend GOT 重绑(asm 蹦床保参) — 它发出的每次消息调用全可见
        {"objc_msgSend", (void *)mf_msgSendTramp, (void **)&g_vOrigMsgSendPtr},
    };
    int r = rebind_symbols_image((void *)g_capDylibBase, (intptr_t)g_capDylibBase, rbs, 8);
    mfLog(@"[capture] vendor-dylib tap v2: %d (vm_protect=%p msgSend=%p)", r, g_vOrigVMProtect, g_vOrigMsgSendPtr);
}

static NSString *const kCapBID = @"com.magicgroot.gooby";
static NSString *const kCapVersion = @"3.0.5";
static NSString *const kCapDylib = @"/var/jb/usr/lib/MinisFix/ReflixPatch-3.0.5.dylib";
static const NSTimeInterval kCapPollSec = 0.5;   // v2.27.1: 2s→0.5s 逮瞬时 swizzle
static const uint32_t kCapMaxEvents = 256;

static NSString *mfCapHex(const uint8_t *p, size_t n) {
    static const char h[] = "0123456789abcdef";
    if (!p || !n) return @"";
    if (n > 256) n = 256;
    char *s = malloc(n * 2 + 1);
    if (!s) return @"";
    for (size_t i = 0; i < n; i++) {
        s[i * 2] = h[p[i] >> 4];
        s[i * 2 + 1] = h[p[i] & 15];
    }
    s[n * 2] = 0;
    NSString *r = [NSString stringWithUTF8String:s];
    free(s);
    return r;
}

typedef struct {
    uint8_t *base;           // 运行期内存基址(mh 相对寻址算好, 主二进制进程内永不卸载)
    uint8_t *baseline;       // ctor 时刻快照(预触发)
    uint8_t *absBase;        // 绝对地址(sweep 用)
    uint64_t size;
    uint64_t vmaddr;         // 报告坐标: 主程序=unslid vmaddr, dylib 段=镜像相对偏移
    uint64_t fileoff;        // 段文件偏移(报告坐标用)
    BOOL noisy;              // __DATA = 噪声层, 只计数
    char name[20];
} mfCapSeg;

static mfCapSeg g_capSegs[32];
static int g_capNSeg = 0;

// v2.40.1: EXCPROBE 用 — 取 __TEXT 基线快照(ctor 原始字节)
static uint8_t *mfCapSeg0Baseline(uint64_t *outSize) {
    if (g_capNSeg <= 0) return NULL;
    *outSize = g_capSegs[0].size;
    return g_capSegs[0].baseline;
}
static uint32_t g_capEvents = 0;
static uint64_t g_capNoiseBytes = 0;
static uint64_t g_capNoiseTotal = 0;
static uint32_t g_capSweeps = 0;
static BOOL g_capCapLogged = NO;
static BOOL g_capOn = NO;
static dispatch_source_t g_capTimer;
static double g_capT0 = 0;

// imp 基线快照: "cls|sel" -> imp(主二进制类, ctor 时拍) — diff 出任意 imp 变化
static NSMutableDictionary *g_impSnap;

// ===== 层3: NSInvocation 窃听 — dylib 唯一明文手法面(13 个 selector 全是 invocation 链) =====
// v2.29.1 安全化: 2.29.0 在 XPC reply 路径崩(SIGSEGV@NSStringFromSelector strlen 野 selector)
//   铁律: 目标类非主二进制 → 直接放行不碰 selector; 字典操作上锁; selector 先过指针门
static IMP g_origInvoke = NULL, g_origInvokeWTH = NULL;
static NSMutableDictionary *g_invSeen;
static os_unfair_lock g_invLock = OS_UNFAIR_LOCK_INIT;
static uint32_t g_invCount = 0;


static void mfCapLogInv(NSInvocation *inv, const char *via) {
    @try {
        static NSString *g_mainExecStr = nil;
        static dispatch_once_t onceT;
        dispatch_once(&onceT, ^{ g_mainExecStr = [[[NSBundle mainBundle] executablePath] copy]; });
        if (!g_mainExecStr) return;
        id t = [inv target];
        if (!t) return;
        Class c = object_getClass(t);           // 目标有效则类指针安全
        if (!c) return;
        const char *img = class_getImageName(c);
        // v2.31.0: 主二进制 + 内嵌 Frameworks 目标 = 全量(类+selector — dylib 构造的 invocation 目标是合法 selector);
        //          系统框架目标 = 只记类名(永不解析 selector — 2.29.0 SIGSEGV 根源), 类名去重天然有界
        BOOL isMain = img && strstr(img, g_mainExecStr.fileSystemRepresentation) != NULL;
        BOOL embedded = img && strstr(img, "/Frameworks/") != NULL;
        if (isMain || embedded) {
            SEL s = [inv selector];
            if (!s || (uintptr_t)s < 0x1000) return; // 野 selector 指针门
            NSString *selName = NSStringFromSelector(s);
            if (!selName.length) return;
            NSString *key = [NSString stringWithFormat:@"F|%@|%@|%s", NSStringFromClass(c), selName, via];
            os_unfair_lock_lock(&g_invLock);
            BOOL dup = (g_invSeen[key] || g_invCount >= 200);
            if (!dup) { g_invSeen[key] = @YES; g_invCount++; }
            os_unfair_lock_unlock(&g_invLock);
            if (!dup) {
                const char *b = img ? strrchr(img, '/') : NULL;
                mfLog(@"[capture] INVOKE[%s] %@ -> %@ (img=%s)", via, NSStringFromClass(c), selName, b ? b + 1 : "?");
            }
        } else {
            NSString *key = [NSString stringWithFormat:@"S|%@", NSStringFromClass(c)];
            os_unfair_lock_lock(&g_invLock);
            BOOL dup = (g_invSeen[key] || g_invCount >= 200);
            if (!dup) { g_invSeen[key] = @YES; g_invCount++; }
            os_unfair_lock_unlock(&g_invLock);
            if (!dup) mfLog(@"[capture] INV-SYS %@", NSStringFromClass(c));   // 系统目标被 invocation 触碰 = 信号
        }
    } @catch (NSException *e) {}
}
static void mf_invHook(id self, SEL _cmd) {
    mfCapLogInv((NSInvocation *)self, "invoke");
    ((void (*)(id, SEL))g_origInvoke)(self, _cmd);
}
static void mf_invWTHook(id self, SEL _cmd, id target) {
    mfCapLogInv((NSInvocation *)self, "withTarget");
    ((void (*)(id, SEL, id))g_origInvokeWTH)(self, _cmd, target);
}
static void mfCapInstallInvocationTap(void) {
    if (g_origInvoke) return;
    Method m1 = class_getInstanceMethod([NSInvocation class], @selector(invoke));
    Method m2 = class_getInstanceMethod([NSInvocation class], @selector(invokeWithTarget:));
    if (m1) g_origInvoke = method_setImplementation(m1, (IMP)mf_invHook);
    if (m2) g_origInvokeWTH = method_setImplementation(m2, (IMP)mf_invWTHook);
    if (g_origInvoke) mfLog(@"[capture] NSInvocation tap installed");
}

// ===== 层6: NSUserDefaults 写监听 — 验证 "dylib 经 NSUserDefaults 伪造 RC 缓存" 假说 =====
static IMP g_origSetObj = NULL;
static uint32_t g_capCount6 = 0;
static void mf_setObjHook(id self, SEL _cmd, id value, NSString *key) {
    if (key && g_capCount6 < 40) {
        NSString *k = key.lowercaseString;
        if ([k containsString:@"revenuecat"] || [k containsString:@"entitlement"]
            || [k containsString:@"customer"] || [k containsString:@"reflix"]
            || [k containsString:@"purchases"] || [k containsString:@"subscri"]) {
            @try {
                NSString *vs = [value description];
                if (vs.length > 200) vs = [[vs substringToIndex:200] stringByAppendingString:@"…"];
                g_capCount6++;
                mfLog(@"[capture] UD-SET %@ = %@", key, vs);
            } @catch (NSException *e) {}
        }
    }
    ((void (*)(id, SEL, id, NSString *))g_origSetObj)(self, _cmd, value, key);
}

static void mfCapInstallUDTap(void) {
    if (g_origSetObj) return;
    Method m = class_getInstanceMethod([NSUserDefaults class], @selector(setObject:forKey:));
    if (!m) return;
    g_origSetObj = method_setImplementation(m, (IMP)mf_setObjHook);
    mfLog(@"[capture] NSUserDefaults write tap installed");
}

// ===== 层4: 主二进制引用扫描 — "app 是查询方"模型判决(名字引用 + mach 子系统常量) =====
static void mfCapScanMainBinary(void) {
    @try {
        NSString *path = [[NSBundle mainBundle] executablePath];
        NSData *d = [NSData dataWithContentsOfFile:path];
        if (!d) return;
        const uint8_t *p = d.bytes;
        NSUInteger n = d.length;
        const char *pats[] = {"ReflixPatch", "MinisFix", "/var/jb", "proAccessOverride"};
        for (int i = 0; i < 4; i++) {
            size_t pl = strlen(pats[i]);
            const uint8_t *hit = NULL;
            for (NSUInteger off = 0; off + pl <= n; off++)
                if (p[off] == pats[i][0] && memcmp(p + off, pats[i], pl) == 0) { hit = p + off; break; }
            if (hit) {
                char ctx[96] = {0};
                NSUInteger cs = (NSUInteger)(hit - p);
                memcpy(ctx, p + (cs > 24 ? cs - 24 : 0), MIN((NSUInteger)95, n - (cs > 24 ? cs - 24 : 0)));
                mfLog(@"[capture] MAINBIN '%s' @0x%lx ctx=%.95s", pats[i], cs, ctx);
            } else {
                mfLog(@"[capture] MAINBIN '%s' absent", pats[i]);
            }
        }
        // mach 子系统客户端特征: 0x965..0x967(请求) / 0x9c9..0x9cb(应答) u32 出现计数
        const uint32_t *u = (const uint32_t *)p;
        NSUInteger nu = n / 4;
        uint32_t want[6] = {0x965, 0x966, 0x967, 0x9c9, 0x9ca, 0x9cb};
        for (int i = 0; i < 6; i++) {
            uint32_t c = 0;
            for (NSUInteger j = 0; j < nu; j++) if (u[j] == want[i]) c++;
            mfLog(@"[capture] MAINBIN u32 0x%x count=%u", want[i], c);
        }
    } @catch (NSException *e) {}
}

static void mfCapWriteEvent(const mfCapSeg *sg, uint64_t off, uint64_t len,
                            const uint8_t *cur) {
    @try {
        NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MinisFix"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSDictionary *r = @{
            @"seg": [NSString stringWithUTF8String:sg->name],
            @"vmaddr": [NSString stringWithFormat:@"0x%llx", sg->vmaddr + off],
            @"seg_offset": [NSString stringWithFormat:@"0x%llx", off],
            @"file_offset": [NSString stringWithFormat:@"0x%llx", sg->fileoff + off],
            @"length": @(len),
            @"baseline": mfCapHex(sg->baseline + off, (size_t)len),
            @"patched": mfCapHex(cur + off, (size_t)len),
            @"elapsed_s": @([[NSDate date] timeIntervalSinceReferenceDate] - g_capT0),
            @"event": @(g_capEvents),
        };
        NSString *path = [NSString stringWithFormat:@"%@/mfcap_%u_%s_0x%llx.json",
                          dir, g_capEvents, sg->name, off];
        NSData *d = [NSJSONSerialization dataWithJSONObject:r options:NSJSONWritingPrettyPrinted error:nil];
        if (d) [d writeToFile:path atomically:YES];
    } @catch (NSException *e) {}
}

// ===== 层2: ObjC imp 巡检 — dylib swizzle 点白送(imp 指进 dylib 镜像 = 被hook) =====
uint8_t *g_capDylibBase = NULL;
uint64_t g_capDylibSize = 0;
static NSMutableDictionary *g_capSeen;   // "类|sel" -> 每点只报一次

static void mfCapRecordSwizzle(NSString *cls, NSString *sel, uintptr_t imp) {
    NSString *key = [NSString stringWithFormat:@"%@|%@", cls, sel];
    if (g_capSeen[key]) return;
    g_capSeen[key] = @YES;
    uintptr_t off = imp - (uintptr_t)g_capDylibBase;
    @try {
        NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MinisFix"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSDictionary *r = @{@"class": cls, @"selector": sel,
                            @"dylib_offset": [NSString stringWithFormat:@"0x%lx", (unsigned long)off]};
        NSString *path = [NSString stringWithFormat:@"%@/mfcap_swizzle_%@.json", dir,
                          [key stringByReplacingOccurrencesOfString:@"|" withString:@"_"]];
        NSData *d = [NSJSONSerialization dataWithJSONObject:r options:NSJSONWritingPrettyPrinted error:nil];
        if (d) [d writeToFile:path atomically:YES];
    } @catch (NSException *e) {}
    mfLog(@"[capture] SWIZZLE %@ -> %@ dylib_off=0x%lx", cls, sel, (unsigned long)off);
    g_capEvents++;
}

static void mfCapObjcSweep(void) {
    if (!g_capDylibBase) return;
    NSString *mainPath = [[NSBundle mainBundle] executablePath] ?: @"";
    unsigned int ncls = 0;
    Class *classes = objc_copyClassList(&ncls);
    if (!classes) return;
    for (unsigned int i = 0; i < ncls; i++) {
        NSString *cn = NSStringFromClass(classes[i]);
        const char *img = class_getImageName(classes[i]);
        BOOL isMain = img && mainPath.length && strstr(img, mainPath.fileSystemRepresentation) != NULL;
        for (int pass = 0; pass < 2; pass++) {
            Class target = pass == 0 ? classes[i] : object_getClass(classes[i]); // 实例方法/类方法
            unsigned int nm = 0;
            Method *ms = class_copyMethodList(target, &nm);
            for (unsigned int j = 0; j < nm; j++) {
                uintptr_t v = (uintptr_t)method_getImplementation(ms[j]);
                if (v >= (uintptr_t)g_capDylibBase && v < (uintptr_t)g_capDylibBase + g_capDylibSize) {
                    mfCapRecordSwizzle(cn, NSStringFromSelector(method_getName(ms[j])), v);
                }
                // v2.27.1 imp diff: 主二进制类的 imp 任意变化都报(瞬时 swizzle 的 0.5s 窗口捕获)
                if (isMain && g_impSnap) {
                    NSString *key = [NSString stringWithFormat:@"%@|%@|%@", cn,
                                     NSStringFromSelector(method_getName(ms[j])), pass ? @"+" : @"-"];
                    NSNumber *old = g_impSnap[key];
                    if (old && old.unsignedLongLongValue != v) {
                        Dl_info info; const char *zone = "unknown";
                        if (dladdr((void *)v, &info) && info.dli_fname) {
                            const char *b = strrchr(info.dli_fname, '/');
                            zone = b ? b + 1 : info.dli_fname;
                        }
                        mfLog(@"[capture] IMPCHG %s[%@%@] 0x%llx→0x%llx zone=%s",
                              pass ? "+" : "-", cn, NSStringFromSelector(method_getName(ms[j])),
                              (unsigned long long)old.unsignedLongLongValue, (unsigned long long)v, zone);
                        if (g_impSnap) g_impSnap[key] = @(v);
                        g_capEvents++;
                    } else if (!old) {
                        g_impSnap[key] = @(v);
                    }
                }
            }
            free(ms);
        }
    }
    free(classes);
}

// imp 基线: 主二进制类全方法表(ctor, 激活前) — 只建一次
static void mfCapBuildImpBaseline(void) {
    if (g_impSnap) return;
    g_impSnap = [NSMutableDictionary dictionary];
    NSString *mainPath = [[NSBundle mainBundle] executablePath] ?: @"";
    unsigned int ncls = 0;
    Class *classes = objc_copyClassList(&ncls);
    if (!classes) return;
    unsigned long cnt = 0;
    for (unsigned int i = 0; i < ncls; i++) {
        const char *img = class_getImageName(classes[i]);
        if (!img || !mainPath.length || !strstr(img, mainPath.fileSystemRepresentation)) continue;
        NSString *cn = NSStringFromClass(classes[i]);
        for (int pass = 0; pass < 2; pass++) {
            Class target = pass == 0 ? classes[i] : object_getClass(classes[i]);
            unsigned int nm = 0;
            Method *ms = class_copyMethodList(target, &nm);
            for (unsigned int j = 0; j < nm; j++) {
                NSString *key = [NSString stringWithFormat:@"%@|%@|%@", cn,
                                 NSStringFromSelector(method_getName(ms[j])), pass ? @"+" : @"-"];
                g_impSnap[key] = @((unsigned long long)method_getImplementation(ms[j]));
                cnt++;
            }
            free(ms);
        }
    }
    free(classes);
    mfLog(@"[capture] imp baseline: %lu methods of main-binary classes", cnt);
}

static void mfCapLocateDylib(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "ReflixPatch")) {
            const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
            if (h && h->magic == MH_MAGIC_64) {
                // load commands 求 __LINKEDIT 段末 = 镜像 vm 范围
                const uint8_t *p = (const uint8_t *)(h + 1);
                uint64_t end = 0;
                for (uint32_t k = 0; k < h->ncmds; k++) {
                    const struct load_command *lc = (const struct load_command *)p;
                    if (lc->cmdsize < sizeof(*lc)) break;
                    if (lc->cmd == LC_SEGMENT_64) {
                        const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
                        if (sg->vmaddr + sg->vmsize > end) end = sg->vmaddr + sg->vmsize;
                    }
                    p += lc->cmdsize;
                }
                g_capDylibBase = (uint8_t *)h;
                g_capDylibSize = end ?: 0x1e4000;   // dylib 段 vmaddr 从 0 起, 镜像内偏移即范围
                mfLog(@"[capture] dylib in-proc @%p size=0x%llx (imp sweep armed)", g_capDylibBase, (unsigned long long)g_capDylibSize);
            }
            return;
        }
    }
}

// v2.34.0: add_image 回调 — dyld 在映射+bind 完、initializer 之前触发本回调
// 这里武装 vendor 全套 GOT 钩(msgSend 蹦床/vm_protect/mach/解析明文) + 预 ctor 段快照
// → 它 ctor 的每一步都从我们的钩子里过(此前 380ms 暗窗的补丁)
static void mf_vendorAddImageCB(const struct mach_header *h, intptr_t slide) {
    @try {
        if (g_capDylibBase) return;   // 已定位(仅一次)
        const char *nm = NULL;
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            if ((const void *)_dyld_get_image_header(i) == (const void *)h) { nm = _dyld_get_image_name(i); break; }
        }
        if (!nm || !strstr(nm, "ReflixPatch")) return;
        const struct mach_header_64 *mh = (const struct mach_header_64 *)h;
        if (mh->magic != MH_MAGIC_64) return;
        g_capDylibBase = (uint8_t *)h;
        const uint8_t *p = (const uint8_t *)(mh + 1);
        uint64_t end = 0;
        for (uint32_t k = 0; k < mh->ncmds; k++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize < sizeof(*lc)) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
                if (sg->vmaddr + sg->vmsize > end) end = sg->vmaddr + sg->vmsize;
            }
            p += lc->cmdsize;
        }
        g_capDylibSize = end ?: 0x1e4000;
        // 预 ctor 段快照(此后它 ctor 写自身状态 = 可见)
        const uint8_t *dp = (const uint8_t *)(mh + 1);
        for (uint32_t k = 0; k < mh->ncmds && g_capNSeg < 32; k++) {
            const struct load_command *lc = (const struct load_command *)dp;
            if (lc->cmdsize < sizeof(*lc)) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sgp = (const struct segment_command_64 *)dp;
                BOOL isD = !strncmp(sgp->segname, "__DATA", 16);
                BOOL isDC = !strncmp(sgp->segname, "__DATA_CONST", 16);
                if (((isD && !isDC) || isDC) && sgp->vmsize > 0 && sgp->vmsize <= 2ULL*1024*1024 && g_capNSeg < 30) {
                    mfCapSeg *sg = &g_capSegs[g_capNSeg];
                    memset(sg, 0, sizeof(*sg));
                    snprintf(sg->name, 19, "dylib.%s", sgp->segname);
                    sg->base = sg->absBase = (uint8_t *)h + sgp->vmaddr;
                    sg->vmaddr = sgp->vmaddr;
                    sg->fileoff = sgp->fileoff;
                    sg->size = sgp->vmsize;
                    sg->noisy = NO;
                    sg->baseline = malloc((size_t)sgp->vmsize);
                    if (sg->baseline) {
                        memcpy(sg->baseline, sg->absBase, (size_t)sgp->vmsize);
                        g_capNSeg++;
                    }
                }
            }
            dp += lc->cmdsize;
        }
        // 武装全部 GOT 钩 — 此刻它的 initializer 还没跑
        mfCapTapVendorDylib();
        mfLog(@"[capture] ★ VENDOR PRE-ARMED @%p size=0x%llx (pre-ctor, initializer not yet run)",
              h, (unsigned long long)g_capDylibSize);
    } @catch (NSException *e) {
        mfLog(@"[capture] add_image cb exception: %@", e);
    }
}

static void mfCapDoSweep(void);

void mfProcCaptureStart(void) {
    if (g_capOn) return;
    NSString *bid = [NSBundle mainBundle].bundleIdentifier;
    NSString *ver = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    if (![bid isEqualToString:kCapBID] || ![ver isEqualToString:kCapVersion]) return;

    // v2.28.1: debug 通道已证伪(2.28.0 实测写入正确域仍不亮) — 默认关, 别污染采集对照
    if ([[NSUserDefaults standardUserDefaults] boolForKey:@"mfDebugOverride"]) {
        NSString *dbg = @"com.reflix.debug.proAccessOverride";
        id cur = [[NSUserDefaults standardUserDefaults] objectForKey:dbg];
        if (![cur isKindOfClass:[NSString class]] || ![cur isEqualToString:@"active"]) {
            [[NSUserDefaults standardUserDefaults] setObject:@"active" forKey:dbg];
            [[NSUserDefaults standardUserDefaults] synchronize];
            mfLog(@"[mfdbg] proAccessOverride -> active (was %@)", cur ?: @"nil");
        } else {
            mfLog(@"[mfdbg] proAccessOverride already active");
        }
    }

    const struct mach_header_64 *mh = NULL;
    intptr_t mainSlide = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE) {
            mh = (const struct mach_header_64 *)h;
            mainSlide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!mh) return;

    // 段表解析 + 快照。主二进制 __PIE__: 运行期地址 = mh + (vmaddr - __TEXT.vmaddr)
    uint64_t textVM = 0;
    {
        const uint8_t *q = (const uint8_t *)(mh + 1);
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)q;
            if (lc->cmdsize < sizeof(*lc)) break;
            if (lc->cmd == LC_SEGMENT_64 &&
                !strncmp(((const struct segment_command_64 *)q)->segname, "__TEXT", 16)) {
                textVM = ((const struct segment_command_64 *)q)->vmaddr;
                break;
            }
            q += lc->cmdsize;
        }
    }
    if (!textVM) { mfLog(@"[capture] __TEXT vmaddr not found"); return; }

    const uint8_t *p = (const uint8_t *)(mh + 1);
    uint64_t totalSnap = 0;
    for (uint32_t i = 0; i < mh->ncmds && g_capNSeg < 32; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(*lc)) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sgp = (const struct segment_command_64 *)p;
            BOOL isText = !strncmp(sgp->segname, "__TEXT", 16);
            BOOL isDC   = !strncmp(sgp->segname, "__DATA_CONST", 16);
            BOOL isData = !strncmp(sgp->segname, "__DATA", 16) && !isDC;
            if ((isText || isDC || isData) && sgp->vmsize > 0 &&
                totalSnap + sgp->vmsize <= 144ULL * 1024 * 1024) {
                uint8_t *abs = (uint8_t *)((uintptr_t)mh + (sgp->vmaddr - textVM));
                uint8_t *snap = malloc((size_t)sgp->vmsize);
                if (snap) {
                    mfCapSeg *sg = &g_capSegs[g_capNSeg];
                    memset(sg, 0, sizeof(*sg));
                    strncpy(sg->name, sgp->segname, 19);
                    sg->base = sg->absBase = abs;
                    sg->baseline = snap;
                    sg->size = sgp->vmsize;
                    sg->vmaddr = sgp->vmaddr;
                    sg->fileoff = sgp->fileoff;
                    sg->noisy = isData;
                    memcpy(snap, abs, (size_t)sgp->vmsize);   // 预触发快照
                    totalSnap += sgp->vmsize;
                    g_capNSeg++;
                    mfLog(@"[capture] baseline@ctor %s vm=0x%llx size=0x%llx @%p",
                          sg->name, sg->vmaddr, sg->size, abs);
                }
            }
        }
        p += lc->cmdsize;
    }
    // v2.34.0: 内嵌框架段快照 — patch 可能打在 RC/TCA 框架(此前从未监视)
    {
        uint32_t fwCount = 0;
        for (uint32_t i = 0; i < _dyld_image_count() && g_capNSeg < 32; i++) {
            const char *nm = _dyld_get_image_name(i);
            if (!nm || !strstr(nm, "/Frameworks/")) continue;
            const struct mach_header_64 *fh = (const struct mach_header_64 *)_dyld_get_image_header(i);
            if (!fh || fh->magic != MH_MAGIC_64) continue;
            const uint8_t *fp = (const uint8_t *)(fh + 1);
            const char *bn = strrchr(nm, '/');
            for (uint32_t k = 0; k < fh->ncmds && g_capNSeg < 32; k++) {
                const struct load_command *lc = (const struct load_command *)fp;
                if (lc->cmdsize < sizeof(*lc)) break;
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *sgp = (const struct segment_command_64 *)fp;
                    BOOL isT = !strncmp(sgp->segname, "__TEXT", 16);
                    BOOL isDC = !strncmp(sgp->segname, "__DATA_CONST", 16);
                    // v2.35.0: RevenueCat 框架 __DATA 也收(ctor 直接写 RW 区栽指针的头号目标)
                    char lw[256]; snprintf(lw, sizeof lw, "%s", nm);
                    for (char *q = lw; *q; q++) if (*q >= 'A' && *q <= 'Z') *q += 32;
                    BOOL isRC = strstr(lw, "revenuecat") != NULL;
                    BOOL isD = !strncmp(sgp->segname, "__DATA", 16) && !isDC;
                    if (((isT || isDC || (isD && isRC))) && sgp->vmsize > 0 && sgp->vmsize <= 12ULL*1024*1024
                        && totalSnap + sgp->vmsize <= 144ULL * 1024 * 1024) {
                        // 标准公式: abs = slide + vmaddr (v2.34.1, fh+vmaddr 在 __TEXT.vmaddr≠0 的框架上读飞)
                        intptr_t fslide = _dyld_get_image_vmaddr_slide(i);
                        uint8_t *abs = (uint8_t *)((uintptr_t)fslide + (uintptr_t)sgp->vmaddr);
                        uint8_t *snap = malloc((size_t)sgp->vmsize);
                        if (snap) {
                            // 内核预检: 不可读段直接跳过(v2.34.0 在 0x3519a0000 SIGSEGV 的教训)
                            vm_size_t br = 0;
                            kern_return_t krr = vm_read_overwrite(mach_task_self(),
                                (vm_address_t)abs, sgp->vmsize, (vm_address_t)snap, &br);
                            if (krr != KERN_SUCCESS || br != sgp->vmsize) {
                                free(snap);
                                mfLog(@"[capture] fw seg unreadable %s.%s @%p kr=%d — skip",
                                      bn ? bn : "?", sgp->segname, abs, krr);
                                fp += lc->cmdsize; continue;
                            }
                            mfCapSeg *sg = &g_capSegs[g_capNSeg];
                            memset(sg, 0, sizeof(*sg));
                            snprintf(sg->name, 19, "fw%s.%s", bn ? bn : "?", sgp->segname);
                            sg->base = sg->absBase = abs;
                            sg->baseline = snap;
                            sg->size = sgp->vmsize;
                            sg->vmaddr = sgp->vmaddr;
                            sg->fileoff = sgp->fileoff;
                            sg->noisy = NO;
                            memcpy(snap, abs, (size_t)sgp->vmsize);
                            totalSnap += sgp->vmsize;
                            g_capNSeg++; fwCount++;
                        }
                    }
                }
                fp += lc->cmdsize;
            }
        }
        mfLog(@"[capture] framework segments snapshotted: %u", fwCount);
    }
    if (!g_capNSeg) { mfLog(@"[capture] no segments snapshotted"); return; }

    g_capT0 = [[NSDate date] timeIntervalSinceReferenceDate];
    g_capOn = YES;
    g_capSeen = [NSMutableDictionary dictionary];
    // 层2 就位: 先拍 imp 基线(必须在 dlopen 之前! 否则 dylib ctor 期 swizzle 被基线吃掉, IMPCHG 失明)
    mfCapBuildImpBaseline();
    // v2.34.0: 窃听链整体提前 — invocation/UD tap 必须先于 vendor ctor 就位
    g_invSeen = [NSMutableDictionary dictionary];
    mfCapInstallInvocationTap();
    mfCapInstallUDTap();
    // v2.38.0: 被劫持符号摸底 — dladdr 反查为主, CAND 扩表为辅
    {
        const char *cands[] = {"mach_msg","mach_msg2","mach_msg_overwrite","mach_msg_send",
            "mach_port_allocate","mach_port_insert_right","mach_port_deallocate",
            "task_get_special_port","task_set_special_port","task_set_exception_ports",
            "mach_ports_register","mach_ports_lookup","sysctlbyname","strcmp","memcmp",
            "mach_port_get_attributes","mach_port_set_attributes","mach_port_kobject",
            "mach_port_extract_right","mach_port_get_context","mach_port_set_context",
            "mach_port_request_notification","mach_port_get_set_status","mach_port_space_info",
            "task_suspend","task_resume","task_info","thread_create","thread_get_state",
            "thread_set_state","semaphore_create","mach_reply_port","task_self_trap",
            "host_get_special_port","task_get_exc_ports","task_swap_exception_ports"};
        void *h = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW | RTLD_LOCAL);
        for (int i = 0; i < 36; i++) {
            void *p = dlsym(h, cands[i]);
            mfLog(@"[capture] CAND %s = %p", cands[i], p);
        }
    }
    // v2.37.0: 终局复刻 — dylib 唯一解锁功能 = hook -[RCEntitlementInfo isActive]
    //   (机制实证: 它 vm_protect 主二进制 __DATA_CONST RW 后直写 4 字节相对 IMP @+0x8ce8)
    //   ★ v2.38.0 证伪: 2.38.0 实测 — mfkill 先动(07.574) → dylib ctor 读 isActive 原始 IMP
    //   做反篡改校验(读到我们的桩 ext+0x0) → 拒绝发 license → ProPaywall 照弹。
    //   mfkill 必须默认 OFF(不污染 dylib 的校验面), 仅 mfKillIsActive=1 时启用作孤立实验。
    if ([[NSUserDefaults standardUserDefaults] boolForKey:@"mfKillIsActive"]) {
    @try {
        Class rcEnt = objc_getClass("RCEntitlementInfo");
        Method m = rcEnt ? class_getInstanceMethod(rcEnt, @selector(isActive)) : NULL;
        if (m) {
            __block BOOL (*orig)(id, SEL) = (BOOL (*)(id, SEL))method_getImplementation(m);
            IMP newImp = imp_implementationWithBlock(^(id self) {
                return YES;   // entitlement 永远活跃
            });
            method_setImplementation(m, newImp);
            (void)orig;
            mfLog(@"[mfkill] RCEntitlementInfo.isActive → YES (dylib equivalent, vendor retired)");
        } else {
            mfLog(@"[mfkill] RCEntitlementInfo/isActive not found");
        }
    } @catch (NSException *e) {
        mfLog(@"[mfkill] exception: %@", e);
    }
    } // mfKillIsActive gate
    // v2.39.8: 运行时 __TEXT trap 扫描 — brk 是 vendor ctor 暗窗写进 app __TEXT 的(解密 dump 无此指令)
    //   原生 C 循环毫秒级: 扫全部 brk(imm>=0x100) 与 udf(imm>=0x100), 与文件对照 = 完整 patch 图
    {
        uint64_t t0 = mach_absolute_time();
        struct mach_header_64 *mh2 = (struct mach_header_64 *)mh;
        mhCapMainText = (uint8_t *)mh2;
        uint8_t *text = (uint8_t *)mh2 + 0;   // __TEXT 从镜像头开始, vm offset==file offset
        uint64_t tsize = 0x2e30000;
        uint32_t *w = (uint32_t *)text;
        uint64_t n = tsize / 4;
        uint32_t found = 0;
        for (uint64_t i = 4; i < n; i++) {
            uint32_t insn = w[i];
            uint32_t imm = 0;
            int isBrk = (insn & 0xFFE0001F) == 0xD4200000;   // brk: imm 在 bits5-20
            int isUdf = (insn & 0xFFFF0000) == 0x00000000;   // udf: 编码 0x00000000, imm 恒 0
            if (isBrk) imm = (insn >> 5) & 0xFFFF;
            if ((isBrk && imm >= 0x100) || isUdf) {
                if (found < 60)
                    mfLog(@"[capture] TRAP %s #%#x @main+0x%llx", isBrk ? "brk" : "udf",
                          imm, (unsigned long long)(i * 4));
                found++;
            }
        }
        // 崩溃四坐标原始字节
        for (int k = 0; k < 4; k++) {
            static const uint64_t cos[4] = {0x14211bc, 0x11d527c, 0x11d6d4c, 0x11d727c};
            uint64_t o = cos[k];
            mfLog(@"[capture] LIVE 0x%llx: %02x%02x%02x%02x", (unsigned long long)o,
                  text[o], text[o+1], text[o+2], text[o+3]);
        }
        mfLog(@"[capture] TRAPSCAN done found=%u (dt=%llums)", found,
              (unsigned long long)((mach_absolute_time() - t0) / 1000000));
    }
    // v2.46.0: ★ 内联补丁(替代件终形态) — 机制终案: vendor 的一切 = 把 main+0x14211bc
    //   的 ldur x9,[x29,#-0x100](f85003a9, 解码字段加载) 换成陷阱, 异常应答 x9=1 跳过原指令
    //   = "该字段恒 1"。等价内联: 直接写 mov x9,#1(0xd2800029) — 无异常无端口无 vendor
    {
        uint64_t siteOff = 0x14211bc;
        uint32_t expect = 0xf85003a9, patch = 0xd2800029;   // mov x9, #1
        volatile uint32_t *siteP = (volatile uint32_t *)(mhCapMainText + siteOff);
        uint32_t cur = *siteP;
        if (cur == expect) {
            kern_return_t kp = vm_protect(mach_task_self(), (vm_address_t)mhCapMainText,
                                          0x2e30000, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
            if (kp == KERN_SUCCESS) {
                *siteP = patch;
                uint32_t chk = *siteP;
                kern_return_t kr3 = vm_protect(mach_task_self(), (vm_address_t)mhCapMainText,
                                               0x2e30000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
                mfLog(@"[capture] INLINE-PATCH 0x14211bc f85003a9→%08x chk=%08x rxs kr=%d patch_kr=%d",
                      patch, chk, kr3, kp);
            } else {
                mfLog(@"[capture] INLINE-PATCH vm_protect kr=%d — 走 EXCPROBE 路径", kp);
            }
        } else {
            mfLog(@"[capture] INLINE-PATCH skip: live=%08x ≠ %08x", cur, expect);
        }
    }
    // v2.34.0 核心: add_image 回调 — dyld 映射完镜像、initializer 执行之前触发
    //   回调里武装 vendor 全套 GOT 钩 + 预 ctor 段快照 → 它 ctor 的每一步都在监视下
    _dyld_register_func_for_add_image(mf_vendorAddImageCB);
    mfLog(@"[capture] add_image callback registered (pre-dlopen)");
    mfCapLocateDylib();
    if (!g_capDylibBase) {
        // v2.28.1: dlopen 兜底默认 ON(采集工作模式 — 增强采集需要 dylib 在场被逮)
        if ([[NSUserDefaults standardUserDefaults] objectForKey:@"mfCaptureDlopen"] == nil
            || [[NSUserDefaults standardUserDefaults] boolForKey:@"mfCaptureDlopen"]) {
            void *h = dlopen(kCapDylib.UTF8String, RTLD_NOW | RTLD_LOCAL);
            if (h) { mfLog(@"[capture] dlopened vendor dylib (fallback)"); mfCapLocateDylib();
                     mfCapObjcSweep();      // ctor 期 swizzle
                     mfCapDoSweep();        // v2.35.0: ctor 期写入现场 — 全段立即 diff(含 RC 框架 __DATA)
            }
            else { const char *de = dlerror();
                   mfLog(@"[capture] vendor dylib dlopen FAILED: %s", de ?: "unknown"); }
        } else {
            mfLog(@"[capture] vendor dylib absent (dlopen fallback OFF) — clean-run mode");
        }
    }
    // v2.27.1: dylib 自身 __DATA/__bss 状态区快照(激活证据层)
    if (g_capDylibBase) {
        const uint8_t *dp = (const uint8_t *)g_capDylibBase;
        const struct mach_header_64 *dh = (const struct mach_header_64 *)g_capDylibBase;
        dp = (const uint8_t *)(dh + 1);
        for (uint32_t k = 0; k < dh->ncmds && g_capNSeg < 32; k++) {
            const struct load_command *lc = (const struct load_command *)dp;
            if (lc->cmdsize < sizeof(*lc)) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sgp = (const struct segment_command_64 *)dp;
                BOOL isD = !strncmp(sgp->segname, "__DATA", 16);
                BOOL isDC = !strncmp(sgp->segname, "__DATA_CONST", 16);
                if ((isD && !isDC) || isDC) {   // v2.28.0: __DATA_CONST 也盯(__got 自体 fishhook 隐身点)
                    mfCapSeg *sg = &g_capSegs[g_capNSeg];
                    memset(sg, 0, sizeof(*sg));
                    snprintf(sg->name, 19, "dylib.%s", sgp->segname);
                    sg->base = sg->absBase = (uint8_t *)g_capDylibBase + sgp->vmaddr;
                    sg->vmaddr = sgp->vmaddr;       // dylib 段从 0 起 = 相对偏移
                    sg->fileoff = sgp->fileoff;
                    sg->size = MIN(sgp->vmsize, 2ULL * 1024 * 1024); // dylib.__DATA 0x48000 实际
                    sg->noisy = NO;
                    sg->baseline = malloc((size_t)sg->size);
                    if (sg->baseline) {
                        memcpy(sg->baseline, sg->absBase, (size_t)sg->size);
                        g_capNSeg++;
                        mfLog(@"[capture] dylib state watch %s off=0x%llx size=0x%llx", sg->name, sg->vmaddr, sg->size);
                    }
                }
            }
            dp += lc->cmdsize;
        }
        // imp 基线已在 dlopen 之前拍完(见上) — 这里不再重复
    }
    // v2.29.0: 审讯层 — 主二进制引用扫描(invocation/UD 窃听已提前到 dlopen 之前, v2.34.0)
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ mfCapScanMainBinary(); });
    // v2.30.0: 层5 — 主二进制 mach_msg/mach_msg2 重绑(license 客户端握手双向捕获)
    if (mh) {
        mfCapInstallMachTap(mh, mainSlide);
        struct rebinding rb2 = {"mach_msg2", (void *)mf_machMsg2Hook, (void **)&g_origMachMsg2};
        int r2 = rebind_symbols_image((void *)mh, mainSlide, &rb2, 1);
        mfLog(@"[capture] main-image mach_msg2 rebind: %d (hook=%p)", r2, g_origMachMsg2);
    }
    // v2.38.5: EXCPORTS 基线(dlopen 前) — ctor 前后对比实锤 dylib 注册行为
    {
        exception_mask_t bm[32]; mach_msg_type_number_t bc = 32;
        mach_port_t bp[32]; exception_behavior_t bb[32]; thread_state_flavor_t bf[32];
        kern_return_t krb = task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, bm, &bc,
                                                     bp, bb, bf);
        uint32_t live = 0;
        for (uint32_t j = 0; krb == KERN_SUCCESS && j < bc && j < 32; j++)
            if (bp[j] != MACH_PORT_NULL) {
                mfLog(@"[capture] EXCPORTS-PRE[%u] mask=0x%x port=0x%x beh=%d flv=%d", j, bm[j], bp[j], bb[j], bf[j]);
                live++;
            }
        if (!live) mfLog(@"[capture] EXCPORTS-PRE none (kr=%d)", krb);
    }
    // v2.32.0: 层7 — vendor dylib 自身 syscall 窃听(服务端循环视角)
    mfCapTapVendorDylib();
    // v2.38.2: 层9 — thread_get_state 链式捕获(定案 0x2a0a0 拦截器语义)
    //   dladdr 实锤: dylib ctor 把主二进制 GOT 的 thread_get_state 槽(__DATA_CONST+0x8ce8)
    //   改写到 dylib+0x2a0a0 拦截器 — app 的 license 查询走这条走私通道。
    //   ★ v2.38.3: 3s 延迟实测错过全部查询(app 的查询在启动头 3s 内跑完, TGS# 0 条)
    //   → dlopen 同步返回 = ctor 已写完槽位, 立即上链, 赶在 app main 之前。
    //   2.38.2 已验证: hook 精确抓到拦截器(0x10bcd20a0 = dylib+0x2a0a0, 与基址 0x10bca8000 对号)。
    if (mh) mfCapInstallTgsChain((struct mach_header_64 *)mh, mainSlide);
    // v2.38.4: 补漏 MIG 客户端面 — mach_msg_send / mach_msg_overwrite
    {
        struct rebinding rbs[2] = {
            {"mach_msg_send", (void *)mf_machMsgSendHook, (void **)&g_origMachMsgSend},
            {"mach_msg_overwrite", (void *)mf_machMsgOverwriteHook, (void **)&g_origMachMsgOverwrite},
        };
        int r34 = rebind_symbols_image((void *)mh, mainSlide, rbs, 2);
        mfLog(@"[capture] main-image send/overwrite rebind: %d send=%p overwrite=%p",
              r34, g_origMachMsgSend, g_origMachMsgOverwrite);
    }
    g_capTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(g_capTimer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kCapPollSec * NSEC_PER_SEC)),
                              (uint64_t)(kCapPollSec * NSEC_PER_SEC), (uint64_t)(0.5 * NSEC_PER_SEC));

    dispatch_source_set_event_handler(g_capTimer, ^{
        mfCapDoSweep();
    });
    mfLog(@"[capture] ON segs=%d snap=%.1fMB poll=%.1fs (passive, no hooks)",
          g_capNSeg, totalSnap / 1048576.0, kCapPollSec);
}

// v2.35.0: sweep 抽函数 — 定时器与 dlopen 后立即扫描共用
static void mfCapDoSweep(void) {
    {
        if (g_capEvents >= kCapMaxEvents) return;
        g_capSweeps++;
        // v2.39.10: 瞬时 brk 猎捕 — vendor JIT 打 brk 进 __TEXT 又自清, 常驻扫描不可见
        //   每 sweep(0.5s) 原生全扫, 新 brk(imm>=0x100) 上报(位置+imm+当前字节); 基线集合去重
        {
            static uint8_t *seen = NULL;
            static uint64_t seenN = 0;
            uint64_t n = 0x2e30000 / 4;
            if (!seen) { seen = calloc(n, 1); seenN = n; }
            if (seen && seenN == n) {
                uint32_t *w = (uint32_t *)mhCapMainText;
                for (uint64_t i = 4; i < n; i++) {
                    uint32_t insn = w[i];
                    if ((insn & 0xFFE0001F) == 0xD4200000) {
                        uint32_t imm = (insn >> 5) & 0xFFFF;
                        if (imm >= 0x100 && !seen[i]) {
                            seen[i] = 1;
                            mfLog(@"[capture] JITBRK brk #%#x @main+0x%llx bytes=%02x%02x%02x%02x",
                                  imm, (unsigned long long)(i * 4),
                                  ((uint8_t *)w)[i*4], ((uint8_t *)w)[i*4+1],
                                  ((uint8_t *)w)[i*4+2], ((uint8_t *)w)[i*4+3]);
                        }
                    }
                }
            }
        }
        // 层2 优先: dylib 在进程内才巡检(被 TrollFools 移除 = 永不触发)
        if (g_capDylibBase) mfCapObjcSweep();
        uint64_t noiseNow = 0;
        for (int s = 0; s < g_capNSeg; s++) {
            mfCapSeg *sg = &g_capSegs[s];
            if (!sg->baseline) continue;
            uint8_t *cur = sg->absBase;
            uint64_t hit = 0;
            for (uint64_t i = 0; i < sg->size;) {
                if (sg->baseline[i] == cur[i]) { i++; continue; }
                uint64_t start = i;
                while (i < sg->size && sg->baseline[i] != cur[i]) i++;
                uint64_t len = i - start;
                hit += len;
                if (!sg->noisy && g_capEvents < kCapMaxEvents) {
                    mfCapWriteEvent(sg, start, len, cur);
                    mfLog(@"[capture] #%u %s vm=0x%llx segoff=0x%llx len=%llu %s→%s",
                          g_capEvents, sg->name, sg->vmaddr + start, start,
                          (unsigned long long)len,
                          mfCapHex(sg->baseline + start, 16), mfCapHex(cur + start, 16));
                    // v2.38.0: dladdr 反查 — 4/8 字节写入=指针劫持, 直接问 dyld 被改的是谁
                    if (len == 4 || len == 8) {
                        uint64_t bptr = 0, aptr = 0;
                        if (start + 8 <= sg->size) {
                            memcpy(&bptr, sg->baseline + start, 8);
                            memcpy(&aptr, cur + start, 8);
                        }
                        if (bptr > 0x100000000ULL && aptr > 0x100000000ULL) {
                            Dl_info bi, ai;
                            int bh = dladdr((void*)(uintptr_t)bptr, &bi);
                            int ah = dladdr((void*)(uintptr_t)aptr, &ai);
                            mfLog(@"[capture] TARGET b=0x%llx [%s fbase=%p %s+0x%llx] a=0x%llx [%s fbase=%p %s+0x%llx]",
                                  (unsigned long long)bptr,
                                  bh && bi.dli_fname ? bi.dli_fname : "?",
                                  bh ? bi.dli_fbase : NULL,
                                  bh && bi.dli_sname ? bi.dli_sname : "?",
                                  (bh && bi.dli_saddr) ? (unsigned long long)(bptr - (uintptr_t)bi.dli_saddr) : (unsigned long long)0,
                                  (unsigned long long)aptr,
                                  ah && ai.dli_fname ? ai.dli_fname : "?",
                                  ah ? ai.dli_fbase : NULL,
                                  ah && ai.dli_sname ? ai.dli_sname : "?",
                                  (ah && ai.dli_saddr) ? (unsigned long long)(aptr - (uintptr_t)ai.dli_saddr) : (unsigned long long)0);
                        }
                    }
                    g_capEvents++;
                }
            }
            if (sg->noisy) noiseNow += hit;
            // 基线推进: 已见变化不重报(每个 patch 点只报一次)
            memcpy(sg->baseline, cur, (size_t)sg->size);
        }
        // v2.27.1: __DATA 噪声可见化 — 有增量就累计, 每 40 sweep(20s)汇总一次防刷屏
        if (noiseNow > 0) {
            g_capNoiseTotal += noiseNow;
            if (g_capSweeps % 40 == 0)
                mfLog(@"[capture] __DATA noise +0x%llx this window, total 0x%llu bytes",
                      (unsigned long long)noiseNow, (unsigned long long)g_capNoiseTotal);
        }
        if (g_capEvents >= kCapMaxEvents && !g_capCapLogged) {
            g_capCapLogged = YES;
            mfLog(@"[capture] event cap reached (%u), sweep stops", g_capEvents);
        }
    }
}
