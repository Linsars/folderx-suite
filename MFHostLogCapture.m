// ====== MFHostLogCapture.m — 宿主日志实时捕获 (v2.6.17) ======
// 借鉴 NSLogViewer (abdullah.nslogviewer) 的 pipe+dup2+GCD 引擎:
//   dup 备份原 fd1/fd2 → dup2 接管到管道写端 → 读端 O_NONBLOCK +
//   dispatch_source(DISPATCH_SOURCE_TYPE_READ) 异步排空 → 按\n切行
//   → UTF8 解码失败降级 ASCII → 环形缓冲
// 与 NLV 差异: 缓冲写死 10000(无四档选择器)、开关默认 OFF 且面板内热启停
//   (stop 时 dup2 还原 fd, 不留 hook)。NSLog 同时走 ASL, 接管 stderr 无损旁路。
// 递归安全: handler 内只入缓冲不调 NSLog/mfLog。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

#define HL_MAX_LINES 10000UL
#define HL_TRIM_BATCH 1000UL

static int g_hlPipeRead = -1, g_hlPipeWrite = -1;
static int g_hlOrigStdout = -1, g_hlOrigStderr = -1;
static dispatch_source_t g_hlSource;
static NSMutableData *g_hlPartial;
static NSMutableArray<NSString *> *g_hlLines;
static pthread_mutex_t g_hlLock = PTHREAD_MUTEX_INITIALIZER;
static BOOL g_hlRunning = NO;
static unsigned long long g_hlTotal = 0;

BOOL mfHostLogRunning(void) { return g_hlRunning; }
unsigned long long mfHostLogTotal(void) { return g_hlTotal; }

static NSString *hlTimestamp(void) {
    static NSDateFormatter *fmt;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ fmt = [NSDateFormatter new]; fmt.dateFormat = @"HH:mm:ss.SSS"; });
    return [fmt stringFromDate:[NSDate date]];
}

static void hlAppendLine(NSString *line) {
    if (line.length == 0) return;
    NSString *row = [NSString stringWithFormat:@"%@ %@", hlTimestamp(), line];
    pthread_mutex_lock(&g_hlLock);
    if (!g_hlLines) g_hlLines = [NSMutableArray new];
    [g_hlLines addObject:row];
    g_hlTotal++;
    // 超限批量裁头(逐条 removeObjectAtIndex:0 是 O(n) 抖动)
    if (g_hlLines.count > HL_MAX_LINES) {
        [g_hlLines removeObjectsInRange:NSMakeRange(0, HL_TRIM_BATCH)];
    }
    pthread_mutex_unlock(&g_hlLock);
}

// 按\n切行: 统一攒进 partial, 遇换行才整行解码(UTF8 失败降级 latin1 不丢字节)
static void hlConsumeBytes(const char *bytes, NSUInteger len) {
    const char *p = bytes, *end = bytes + len;
    if (!g_hlPartial) g_hlPartial = [NSMutableData new];
    while (p < end) {
        const char *nl = memchr(p, '\n', end - p);
        NSUInteger segLen = nl ? (NSUInteger)(nl - p) : (NSUInteger)(end - p);
        [g_hlPartial appendBytes:p length:segLen];
        if (nl) {
            NSData *seg = [g_hlPartial copy];
            g_hlPartial.length = 0;
            NSString *s = [[NSString alloc] initWithData:seg encoding:NSUTF8StringEncoding];
            if (!s) s = [[NSString alloc] initWithData:seg encoding:NSISOLatin1StringEncoding];
            hlAppendLine(s);
        }
        p += segLen + (nl ? 1 : 0);
    }
}

static void hlDrain(void) {
    char buf[16384];
    ssize_t n;
    while ((n = read(g_hlPipeRead, buf, sizeof(buf))) > 0) {
        @autoreleasepool {
            hlConsumeBytes(buf, (NSUInteger)n);
        }
    }
    // n<=0: EAGAIN=排空 / EBADF=fd 已还原,静默退出
}

void mfHostLogStart(void) {
    if (g_hlRunning) return;
    int fds[2] = {-1, -1};
    if (pipe(fds) != 0) return;
    g_hlPipeRead = fds[0];
    g_hlPipeWrite = fds[1];

    int fl = fcntl(g_hlPipeRead, F_GETFL, 0);
    if (fl >= 0) fcntl(g_hlPipeRead, F_SETFL, fl | O_NONBLOCK);

    // 备份原 fd 再接管(blocking read 会卡死队列,O_NONBLOCK 是标准姿势)
    g_hlOrigStderr = dup(STDERR_FILENO);
    g_hlOrigStdout = dup(STDOUT_FILENO);
    if (g_hlOrigStderr < 0 || g_hlOrigStdout < 0) return;
    dup2(g_hlPipeWrite, STDERR_FILENO);
    dup2(g_hlPipeWrite, STDOUT_FILENO);

    pthread_mutex_lock(&g_hlLock);
    if (!g_hlLines) g_hlLines = [NSMutableArray new];
    if (!g_hlPartial) g_hlPartial = [NSMutableData new];
    pthread_mutex_unlock(&g_hlLock);

    g_hlSource = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_READ, (uintptr_t)g_hlPipeRead, 0,
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_event_handler(g_hlSource, ^{ hlDrain(); });
    dispatch_source_set_cancel_handler(g_hlSource, ^{
        close(g_hlPipeRead); close(g_hlPipeWrite);
        g_hlPipeRead = g_hlPipeWrite = -1;
    });
    dispatch_resume(g_hlSource);
    g_hlRunning = YES;
    mfLog(@"hostlog ON — stdout/stderr piped (cap 10000 lines)");
}

void mfHostLogStop(void) {
    if (!g_hlRunning) return;
    g_hlRunning = NO;
    if (g_hlSource) { dispatch_source_cancel(g_hlSource); g_hlSource = nil; }
    // 还原 fd —— 关键: 停了就不能让 app 的输出掉进没人读的管道
    if (g_hlOrigStderr >= 0) { dup2(g_hlOrigStderr, STDERR_FILENO); close(g_hlOrigStderr); g_hlOrigStderr = -1; }
    if (g_hlOrigStdout >= 0) { dup2(g_hlOrigStdout, STDOUT_FILENO); close(g_hlOrigStdout); g_hlOrigStdout = -1; }
    // 残余半行吐出来
    pthread_mutex_lock(&g_hlLock);
    if (g_hlPartial.length > 0) {
        NSString *s = [[NSString alloc] initWithData:g_hlPartial encoding:NSUTF8StringEncoding];
        if (!s) s = [[NSString alloc] initWithData:g_hlPartial encoding:NSISOLatin1StringEncoding];
        g_hlPartial.length = 0;
        if (s.length) [g_hlLines addObject:[NSString stringWithFormat:@"%@ %@", hlTimestamp(), s]];
    }
    pthread_mutex_unlock(&g_hlLock);
    mfLog(@"hostlog OFF — fds restored");
}

NSArray<NSString *> *mfHostLogSnapshot(void) {
    pthread_mutex_lock(&g_hlLock);
    NSArray *copy = [g_hlLines copy];
    pthread_mutex_unlock(&g_hlLock);
    return copy ?: @[];
}

unsigned long long mfHostLogBufferedCount(void) {
    pthread_mutex_lock(&g_hlLock);
    unsigned long long c = g_hlLines.count;
    pthread_mutex_unlock(&g_hlLock);
    return c;
}

void mfHostLogClear(void) {
    pthread_mutex_lock(&g_hlLock);
    [g_hlLines removeAllObjects];
    pthread_mutex_unlock(&g_hlLock);
}
