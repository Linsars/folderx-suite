// minisfixd.c — MinisFix 特权充电控制守护进程(v2.6.31)
// 存在理由: IORegistryEntrySetCFProperties 对 power source 需要 com.apple.private.powersource-write
//   entitlement(实测 SB 进程无此权限 kr=0xE0000001); 注入 dylib 无法给宿主进程添加 entitlement,
//   故独立 daemon 持证上岗。对标 ChargeLimiter LaunchDaemon 架构。
// 协议(127.0.0.1:39082, 仅 loopback):
//   收 5B: "MFWR" + cmd(0=停充/1=恢复)
//   回 8B: kr_AppleSmartBattery + kr_IOPMPowerSource (各 uint32 LE)

#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef mach_port_t mf_io_t;
static mach_port_t (*p_IOMasterPort)(mach_port_t, mach_port_t *);
static CFMutableDictionaryRef (*p_IOServiceMatching)(const char *);
static mf_io_t (*p_IOServiceGetMatchingService)(mach_port_t, CFMutableDictionaryRef);
static kern_return_t (*p_IORegistryEntrySetCFProperties)(mf_io_t, CFTypeRef);
static kern_return_t (*p_IOObjectRelease)(mf_io_t);

static int loadIOKit(void) {
    void *h = dlsym(RTLD_DEFAULT, "IOMasterPort");
    if (!h) h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!h) return -1;
    p_IOMasterPort = dlsym(RTLD_DEFAULT, "IOMasterPort");
    p_IOServiceMatching = dlsym(RTLD_DEFAULT, "IOServiceMatching");
    p_IOServiceGetMatchingService = dlsym(RTLD_DEFAULT, "IOServiceGetMatchingService");
    p_IORegistryEntrySetCFProperties = dlsym(RTLD_DEFAULT, "IORegistryEntrySetCFProperties");
    p_IOObjectRelease = dlsym(RTLD_DEFAULT, "IOObjectRelease");
    if (!p_IOMasterPort || !p_IOServiceMatching || !p_IOServiceGetMatchingService ||
        !p_IORegistryEntrySetCFProperties || !p_IOObjectRelease) return -2;
    return 0;
}

// on=YES 恢复充电 / NO=停充(iOS>=13 语义: IsCharging 钉 YES, PredictiveChargingInhibit 总开关)
static kern_return_t writeCharging(const char *svcName, int on) {
    if (!p_IOMasterPort) return 0xE00002C1u; // not privileged 占位
    mach_port_t master = 0;
    p_IOMasterPort(0, &master);
    mf_io_t svc = p_IOServiceGetMatchingService(master, p_IOServiceMatching(svcName));
    if (!svc) return 0xE00002C2u; // no service 占位
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(kCFAllocatorDefault, 3,
        &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(props, CFSTR("IsCharging"), kCFBooleanTrue);
    CFDictionarySetValue(props, CFSTR("PredictiveChargingInhibit"), on ? kCFBooleanFalse : kCFBooleanTrue);
    CFDictionarySetValue(props, CFSTR("ExternalConnected"), on ? kCFBooleanTrue : kCFBooleanFalse);
    kern_return_t kr = p_IORegistryEntrySetCFProperties(svc, props);
    CFRelease(props);
    p_IOObjectRelease(svc);
    return kr;
}

int main(int argc, char **argv) {
    if (loadIOKit() != 0) {
        fprintf(stderr, "[minisfixd] IOKit load failed\n");
        // 不退出: launchd KeepAlive 会疯狂拉起, 睡大觉等下次部署换二进制
        sleep(60);
        return 1;
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return 1;
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(39082);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(lfd); return 1; }
    if (listen(lfd, 4) != 0) { close(lfd); return 1; }
    fprintf(stderr, "[minisfixd] listening 127.0.0.1:39082\n");

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) continue;
        unsigned char hdr[5] = {0};
        ssize_t n = read(cfd, hdr, 5);
        uint32_t krA = 0xE0000001u, krI = 0xE0000001u;
        if (n == 5 && memcmp(hdr, "MFWR", 4) == 0 && (hdr[4] == 0 || hdr[4] == 1)) {
            int on = (int)hdr[4];
            krA = (uint32_t)writeCharging("AppleSmartBattery", on);
            krI = (uint32_t)writeCharging("IOPMPowerSource", on);
            fprintf(stderr, "[minisfixd] write on=%d krASB=0x%x krIOPS=0x%x\n", on, krA, krI);
        }
        uint32_t out[2] = { krA, krI }; // LE host order, 同机通信无字节序问题
        write(cfd, out, 8);
        shutdown(cfd, SHUT_RDWR);
        close(cfd);
    }
    return 0;
}
