// ====== MFBatteryServer.m — 电池数据服务端 (v2.6.26, 仅 SpringBoard) ======
// 背景: 普通 app 沙盒双重限制——IOKit registry 裁剪 + mach-lookup deny(CFMessagePort 不可达)。
//   ChargeLimiter 同场景用 root daemon + GCDWebServer(HTTP) 解决。
//   本服务端对齐该架构: 127.0.0.1:39081 TCP, 协议 = 收"MFBA"魔数回 plist 二进制。
//   loopback 仅本机可达; 电池数据非敏感。

#import <Foundation/Foundation.h>
#import <IOKit/IOMessage.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

typedef mach_port_t bs_io_t;
static mach_port_t (*bs_IOMasterPort)(mach_port_t, mach_port_t *);
static CFMutableDictionaryRef (*bs_IOServiceMatching)(const char *);
static bs_io_t (*bs_IOServiceGetMatchingService)(mach_port_t, CFMutableDictionaryRef);
static kern_return_t (*bs_IORegistryEntryCreateCFProperties)(bs_io_t, CFMutableDictionaryRef *, CFAllocatorRef, UInt32);
static kern_return_t (*bs_IOObjectRelease)(bs_io_t);

static BOOL bsLoadIOKit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlsym(RTLD_DEFAULT, "IOMasterPort");
        if (!h) h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        if (!h) return;
        bs_IOMasterPort = dlsym(RTLD_DEFAULT, "IOMasterPort");
        bs_IOServiceMatching = dlsym(RTLD_DEFAULT, "IOServiceMatching");
        bs_IOServiceGetMatchingService = dlsym(RTLD_DEFAULT, "IOServiceGetMatchingService");
        bs_IORegistryEntryCreateCFProperties = dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperties");
        bs_IOObjectRelease = dlsym(RTLD_DEFAULT, "IOObjectRelease");
    });
    return bs_IOMasterPort != NULL;
}

static NSDictionary *bsReadBattery(void) {
    if (!bsLoadIOKit()) return nil;
    mach_port_t master = 0;
    bs_IOMasterPort(0, &master);
    bs_io_t svc = bs_IOServiceGetMatchingService(master, bs_IOServiceMatching("AppleSmartBattery"));
    if (!svc) svc = bs_IOServiceGetMatchingService(master, bs_IOServiceMatching("IOPMPowerSource"));
    if (!svc) return nil;
    CFMutableDictionaryRef props = NULL;
    if (bs_IORegistryEntryCreateCFProperties(svc, &props, kCFAllocatorDefault, 0) != 0 || !props) {
        bs_IOObjectRelease(svc);
        return nil;
    }
    bs_IOObjectRelease(svc);
    return [(__bridge NSDictionary *)props copy];
}

#define BS_PORT 39081

static void bsFileLog(NSString *line) {
    @try {
        NSString *path = @"/var/mobile/Documents/minisfix_sysenhance.log";
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) { [@"" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]; fh = [NSFileHandle fileHandleForWritingAtPath:path]; }
        if (fh) { [fh seekToEndOfFile]; [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    } @catch (NSException *e) {}
}

static void *bsServerThread(void *arg) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { bsFileLog(@"[battery] socket() failed"); return NULL; }
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(BS_PORT);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        bsFileLog([NSString stringWithFormat:@"[battery] bind :%d FAILED errno=%d", BS_PORT, errno]);
        close(lfd);
        return NULL;
    }
    if (listen(lfd, 4) != 0) { bsFileLog(@"[battery] listen failed"); close(lfd); return NULL; }
    bsFileLog([NSString stringWithFormat:@"[battery] listening ok 127.0.0.1:%d %@", BS_PORT, [NSDate date]]);
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) continue;
        // 魔数握手
        char magic[4] = {0};
        ssize_t n = read(cfd, magic, 4);
        if (n == 4 && memcmp(magic, "MFBA", 4) == 0) {
            @autoreleasepool {
                NSDictionary *props = bsReadBattery();
                NSData *out = [NSPropertyListSerialization dataWithPropertyList:(props ?: @{})
                                                                        format:NSPropertyListBinaryFormat_v1_0
                                                                       options:0 error:NULL];
                uint32_t len = out ? (uint32_t)out.length : 0;
                uint32_t nlen = htonl(len);
                write(cfd, &nlen, 4);
                if (out && len > 0 && len < 1048576) {
                    write(cfd, out.bytes, len);
                }
            }
        }
        shutdown(cfd, SHUT_RDWR);
        close(cfd);
    }
    return NULL;
}

__attribute__((constructor))
static void BatteryServerAutoStart(void) {
    // 双保险: filter=springboard 已定向, 这里再验身份防误注入
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (![bid isEqualToString:@"com.apple.springboard"]) return;

    static dispatch_once_t once;
    dispatch_once(&once, ^{
        pthread_t th;
        if (pthread_create(&th, NULL, bsServerThread, NULL) == 0) {
            pthread_detach(th);
            NSLog(@"[SysEnhance] battery server thread started (127.0.0.1:%d)", BS_PORT);
        } else {
            bsFileLog(@"[battery] pthread_create failed");
        }
    });
}
