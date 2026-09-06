// MFNetworkCapture.m — MinisFix v5.0 网络捕获 + 拦截修改
// 自研轻量版：NSURLProtocol + NSURLSession delegate hook
// 能力：捕获请求/响应（URL/method/headers/body/status/响应body）+ 规则替换（body/header/URL/block）

#import "MFPanel.h"
#import <objc/runtime.h>

// ====== 捕获记录模型（@interface 在 MFPanel.h 共享） ======
@implementation MFNetRecord
@end

// ====== 全局捕获存储 ======
static NSMutableArray *g_capturedRecords = nil;
BOOL g_captureEnabled = NO;
BOOL g_rewriteEnabled = NO;
NSMutableArray *g_rewriteRules = nil;
#define MF_MAX_RECORDS 200

// ====== 拦截规则模型（@interface 在 MFPanel.h 共享） ======
@implementation MFRewriteRule
- (NSDictionary *)toDict {
    NSDictionary *d = @{
        @"pattern": self.pattern ?: @"",
        @"matchType": self.matchType ?: @"contain",
        @"action": self.action ?: @"replaceResp",
        @"urlReplace": self.urlReplace ?: @"",
        @"bodyReplace": self.bodyReplace ?: @"",
        @"headerReplaces": self.headerReplaces ?: @{},
        @"enabled": @(self.enabled),
        @"appBundle": self.appBundle ?: @"",
        @"direction": self.direction ?: @"",
        @"reject": @(self.reject),
        @"name": self.name ?: @"",
        @"reqHeaders": self.reqHeaders ?: @{},
        @"respHeaders": self.respHeaders ?: @{},
        @"reqBody": self.reqBody ?: @"",
        @"respBody": self.respBody ?: @"",
    };
    return d;
}
+ (instancetype)fromDict:(NSDictionary *)d {
    MFRewriteRule *r = [MFRewriteRule new];
    r.pattern = d[@"pattern"];
    r.matchType = d[@"matchType"];
    r.action = d[@"action"];
    r.urlReplace = d[@"urlReplace"];
    r.bodyReplace = d[@"bodyReplace"];
    r.headerReplaces = d[@"headerReplaces"];
    r.enabled = [d[@"enabled"] boolValue];
    r.appBundle = d[@"appBundle"];
    r.direction = d[@"direction"];
    r.reject = [d[@"reject"] boolValue];
    r.name = d[@"name"];
    r.reqHeaders = d[@"reqHeaders"];
    r.respHeaders = d[@"respHeaders"];
    r.reqBody = d[@"reqBody"];
    r.respBody = d[@"respBody"];
    return r;
}
@end

// 当前 app bundle id（规则隔离用）
NSString *mfCurrentBundleId(void) {
    return [[NSBundle mainBundle] bundleIdentifier] ?: @"";
}

// ====== 规则匹配 ======
static BOOL mfRuleMatchesURL(MFRewriteRule *rule, NSString *url) {
    if (!rule.enabled || rule.pattern.length == 0) return NO;
    // 规则隔离：带 appBundle 的规则只对创建它的 app 生效
    if (rule.appBundle.length > 0 && ![rule.appBundle isEqualToString:mfCurrentBundleId()]) return NO;
    NSString *pat = rule.pattern;
    if ([rule.matchType isEqualToString:@"url"]) {
        return [url isEqualToString:pat];
    } else if ([rule.matchType isEqualToString:@"regex"]) {
        NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pat options:0 error:nil];
        return [re firstMatchInString:url options:0 range:NSMakeRange(0, url.length)] != nil;
    } else {  // contain
        return [url containsString:pat];
    }
}

static BOOL mfRuleMatchesDirection(MFRewriteRule *rule, NSString *direction) {
    if (!rule.direction || rule.direction.length == 0) return YES; // nil/空 = 双向
    return [rule.direction isEqualToString:direction];
}

static void mfLoadRules(void) {
    if (g_rewriteRules) return;
    g_rewriteRules = [NSMutableArray new];
    NSArray *arr = mfPrefsDict()[@"mfRewriteRules"];
    for (NSDictionary *d in arr) {
        [g_rewriteRules addObject:[MFRewriteRule fromDict:d]];
    }
}

static void mfSaveRules(void) {
    NSMutableDictionary *d = [mfPrefsDict() mutableCopy];
    NSMutableArray *arr = [NSMutableArray new];
    for (MFRewriteRule *r in g_rewriteRules) [arr addObject:[r toDict]];
    d[@"mfRewriteRules"] = arr;
    [d writeToFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist" atomically:YES];
}

// 保存规则：index<0 追加，否则替换 index 处
void mfSaveRule(MFRewriteRule *rule, NSInteger index) {
    mfLoadRules();
    if (index >= 0 && index < (NSInteger)g_rewriteRules.count) {
        [g_rewriteRules replaceObjectAtIndex:index withObject:rule];
        mfLog(@"rule updated: %@ %@ %@", rule.pattern, rule.matchType, rule.action);
    } else {
        [g_rewriteRules addObject:rule];
        mfLog(@"rule added: %@ %@ %@", rule.pattern, rule.matchType, rule.action);
    }
    mfSaveRules();
}

// 删除规则
void mfRemoveRule(NSInteger index) {
    mfLoadRules();
    if (index >= 0 && index < (NSInteger)g_rewriteRules.count) {
        [g_rewriteRules removeObjectAtIndex:index];
        mfSaveRules();
        mfLog(@"rule removed at %ld", (long)index);
    }
}

// MFPanel.m 调用的接口——添加规则（带当前 app 隔离）
void mfAddRule(NSString *pattern, NSString *matchType, NSString *action) {
    MFRewriteRule *r = [MFRewriteRule new];
    r.pattern = pattern; r.matchType = matchType; r.action = action; r.enabled = YES;
    r.appBundle = mfCurrentBundleId();
    mfSaveRule(r, -1);
}

// 网络分析模块（MFNetAnalyzer.m）读捕获缓冲的只读快照
NSArray *mfCapturedRecordsSnapshot(void) {
    @synchronized (g_capturedRecords) {
        return g_capturedRecords ? [g_capturedRecords copy] : @[];
    }
}

// 开关状态读取（MFNetAnalyzer 页面复用）
BOOL mfCaptureEnabledState(void) { return g_captureEnabled; }

// ====== 记录捕获 ======
static void mfRecordCapture(MFNetRecord *rec) {
    if (!g_captureEnabled) return;
    @synchronized (g_capturedRecords) {
        if (!g_capturedRecords) g_capturedRecords = [NSMutableArray new];
        if (g_capturedRecords.count >= MF_MAX_RECORDS) {
            [g_capturedRecords removeObjectAtIndex:0];
        }
        // 生成简要摘要
        NSString *bodyStr = nil;
        if (rec.respBody.length > 0) {
            bodyStr = [[NSString alloc] initWithData:rec.respBody encoding:NSUTF8StringEncoding];
            if (!bodyStr) bodyStr = [rec.respBody description];
            if (bodyStr.length > 200) bodyStr = [bodyStr substringToIndex:200];
        }
        rec.summary = [NSString stringWithFormat:@"%@ %ld %@",
            rec.method, (long)rec.status, bodyStr ?: @""];
        [g_capturedRecords addObject:rec];
    }
}

// ====== NSURLProtocol 拦截 ======
@interface MFURLProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (strong) NSURLSession *session;
@property (strong) NSMutableData *data;
@property (strong) MFNetRecord *record;
@property (strong) NSURLResponse *response;
@property (strong) NSData *replaceBody;   // replaceResp 预构建的替换 body
@property BOOL replacingBody;             // 是否正在替换 body（原始数据不转发）
@end

@implementation MFURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"MFHandled" inRequest:request]) return NO;
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) return NO;
    // WebSocket upgrade 请求不拦截——NSURLProtocol 无法正确转发 101 Switching Protocols，
    // 会导致上层 NSURLSessionWebSocketTask 状态错乱甚至崩溃（openminis 闪退根因之一）
    NSString *upgrade = request.allHTTPHeaderFields[@"Upgrade"];
    if ([upgrade.lowercaseString containsString:@"websocket"]) return NO;
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    // v2.3.0: 不经 super 分发(Apple 实现回调子类→无限递归→栈溢出 Bus error),
    // 直接 NO——本协议只做拦截改写,不参与 URL 缓存去重
    return NO;
}

- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"MFHandled" inRequest:req];
    
    self.record = [MFNetRecord new];
    self.record.url = req.URL.absoluteString;
    self.record.method = req.HTTPMethod;
    self.record.reqHeaders = req.allHTTPHeaderFields;
    self.record.reqBody = req.HTTPBody;
    self.record.timestamp = [NSDate date];
    
    // 应用请求拦截规则（增强版：direction + reject + 四象限）
    mfLoadRules();
    if (g_rewriteEnabled) {
        for (MFRewriteRule *rule in g_rewriteRules) {
            if (!mfRuleMatchesURL(rule, self.record.url)) continue;
            if (!mfRuleMatchesDirection(rule, @"request")) continue;
            if (rule.reject) {
                // reject: 返回空响应（屏蔽）
                NSURLResponse *resp = [[NSURLResponse alloc] initWithURL:req.URL MIMEType:nil expectedContentLength:0 textEncodingName:nil];
                [self.client URLProtocol:self didReceiveResponse:resp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                self.record.status = 0;
                self.record.summary = @"REJECTED";
                mfRecordCapture(self.record);
                return;
            }
            // 请求侧四象限：reqHeaders / reqBody
            if (rule.reqHeaders && rule.reqHeaders.count > 0) {
                [req setAllHTTPHeaderFields:rule.reqHeaders];
            }
            if (rule.reqBody && rule.reqBody.length > 0) {
                [req setHTTPBody:[rule.reqBody dataUsingEncoding:NSUTF8StringEncoding]];
            }
            // 兼容旧字段
            if (rule.urlReplace.length > 0) {
                NSURL *newURL = [NSURL URLWithString:rule.urlReplace];
                if (newURL) [req setURL:newURL];
            }
            if (rule.bodyReplace.length > 0) {
                [req setHTTPBody:[rule.bodyReplace dataUsingEncoding:NSUTF8StringEncoding]];
            }
            for (NSString *key in rule.headerReplaces) {
                [req setValue:rule.headerReplaces[key] forHTTPHeaderField:key];
            }
        }
    }
    
    // 转发请求
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    self.session = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:req];
    [task resume];
}

- (void)stopLoading {
    [self.session invalidateAndCancel];
}

#pragma mark NSURLSessionDataDelegate

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveResponse:(NSURLResponse *)response
    completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    self.response = response;
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        self.record.status = httpResp.statusCode;
        self.record.respHeaders = httpResp.allHeaderFields;
        self.record.mimeType = httpResp.MIMEType;

        NSHTTPURLResponse *outResp = httpResp;
        NSDictionary *outHeaders = httpResp.allHeaderFields;

        // 响应侧增强规则（direction + reject + 四象限）
        NSData *replBody = nil;
        if (g_rewriteEnabled) {
            mfLoadRules();
            for (MFRewriteRule *rule in g_rewriteRules) {
                if (!mfRuleMatchesURL(rule, self.record.url)) continue;
                if (!mfRuleMatchesDirection(rule, @"response")) continue;
                if (rule.reject) {
                    // reject on response: 返回空 body（屏蔽响应）
                    replBody = [NSData data];
                    outHeaders = @{};
                    outResp = [[NSHTTPURLResponse alloc] initWithURL:httpResp.URL
                                                       statusCode:200
                                                      HTTPVersion:@"HTTP/1.1"
                                                     headerFields:@{}];
                    break;
                }
                // 响应侧四象限：respHeaders / respBody
                if (rule.respHeaders && rule.respHeaders.count > 0) {
                    outHeaders = rule.respHeaders;
                    outResp = [[NSHTTPURLResponse alloc] initWithURL:httpResp.URL
                                                           statusCode:httpResp.statusCode
                                                          HTTPVersion:@"HTTP/1.1"
                                                         headerFields:rule.respHeaders];
                }
                if (rule.respBody && rule.respBody.length > 0) {
                    replBody = [rule.respBody dataUsingEncoding:NSUTF8StringEncoding];
                }
                // 兼容旧字段
                if ([rule.action isEqualToString:@"replaceResp"] && rule.bodyReplace.length > 0) {
                    replBody = [rule.bodyReplace dataUsingEncoding:NSUTF8StringEncoding];
                }
            }
        }
        if (replBody) {
            NSMutableDictionary *hdrs = [outHeaders mutableCopy];
            hdrs[@"Content-Length"] = [NSString stringWithFormat:@"%lu", (unsigned long)replBody.length];
            outResp = [[NSHTTPURLResponse alloc] initWithURL:httpResp.URL
                                                   statusCode:httpResp.statusCode
                                                  HTTPVersion:@"HTTP/1.1"
                                                 headerFields:hdrs];
            self.replaceBody = replBody;
            self.replacingBody = YES;
            self.record.respHeaders = hdrs;
            mfLog(@"replaceResp: body replaced (%lu bytes)", (unsigned long)replBody.length);
        }

        [self.client URLProtocol:self didReceiveResponse:outResp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        self.data = [NSMutableData new];
        completionHandler(NSURLSessionResponseAllow);
        return;
    }
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    self.data = [NSMutableData new];
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    if (self.replacingBody) return;  // 原始 body 不转发（已被规则替换）
    [self.data appendData:data];
    [self.client URLProtocol:self didLoadData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        [self.client URLProtocol:self didFailWithError:error];
        self.record.status = -1;
        self.record.summary = [NSString stringWithFormat:@"ERROR: %@", error.localizedDescription];
    } else {
        if (self.replacingBody && self.replaceBody) {
            // 发送替换后的 body（正常路径数据已在 didReceiveData 转发，此处只发替换 body）
            self.record.respBody = self.replaceBody;
            [self.client URLProtocol:self didLoadData:self.replaceBody];
        } else {
            self.record.respBody = self.data;
        }
        [self.client URLProtocolDidFinishLoading:self];
    }
    mfRecordCapture(self.record);
}

@end

// ====== WebSocket 捕获（参考 FLEX injectWebsocketSendMessage/ReceiveMessage） ======
@interface MFWebSocketRecord : NSObject
@property (copy) NSString *url;
@property (copy) NSString *direction;  // send / receive
@property (copy) NSString *type;       // text / data
@property (copy) NSString *content;
@property (strong) NSDate *timestamp;
@end
@implementation MFWebSocketRecord
@end

static NSMutableArray *g_wsRecords = nil;

static void mfRecordWebSocket(NSString *url, NSString *direction, NSObject *message) {
    if (!g_captureEnabled) return;
    if (!g_wsRecords) g_wsRecords = [NSMutableArray new];
    MFWebSocketRecord *rec = [MFWebSocketRecord new];
    rec.url = url;
    rec.direction = direction;
    rec.timestamp = [NSDate date];
    if ([message isKindOfClass:[NSString class]]) {
        rec.type = @"text";
        rec.content = (NSString *)message;
    } else if ([message isKindOfClass:[NSData class]]) {
        rec.type = @"data";
        rec.content = [[NSString alloc] initWithData:(NSData *)message encoding:NSUTF8StringEncoding] ?: @"<binary>";
    } else {
        // NSURLSessionWebSocketMessage——动态取
        @try {
            SEL sel = NSSelectorFromString(@"string");
            if ([message respondsToSelector:sel]) {
                NSString *s = [message performSelector:sel];
                if ([s isKindOfClass:[NSString class]]) { rec.type = @"text"; rec.content = s; }
            }
            sel = NSSelectorFromString(@"data");
            if (!rec.content && [message respondsToSelector:sel]) {
                NSData *d = [message performSelector:sel];
                if ([d isKindOfClass:[NSData class]]) {
                    rec.type = @"data";
                    rec.content = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: @"<binary>";
                }
            }
        } @catch (NSException *e) {
            rec.content = [message description];
        }
    }
    if (rec.content.length > 2000) rec.content = [rec.content substringToIndex:2000];
    @synchronized (g_wsRecords) {
        [g_wsRecords addObject:rec];
        if (g_wsRecords.count > 200) [g_wsRecords removeObjectAtIndex:0];
    }
    mfLog(@"WS %@ %@ (%@): %@", direction, url, rec.type, rec.content.length > 100 ? [rec.content substringToIndex:100] : rec.content);
}

// hook NSURLSessionWebSocketTask——sendMessage/receiveMessage
static IMP orig_ws_sendMessage;
static void new_ws_sendMessage(id self, SEL _cmd, id message, id completion) {
    NSString *url = [[[self performSelector:NSSelectorFromString(@"originalRequest")] URL] absoluteString] ?: @"?";
    mfRecordWebSocket(url, @"send", message);
    ((void(*)(id, SEL, id, id))orig_ws_sendMessage)(self, _cmd, message, completion);
}
static IMP orig_ws_receiveMessage;
static void new_ws_receiveMessage(id self, SEL _cmd, id completion) {
    NSString *url = [[[self performSelector:NSSelectorFromString(@"originalRequest")] URL] absoluteString] ?: @"?";
    id wrappedCompletion = ^(id message, id error) {
        if (message) mfRecordWebSocket(url, @"recv", message);
        if (completion) {
            void (^origBlock)(id, id) = completion;
            origBlock(message, error);
        }
    };
    ((void(*)(id, SEL, id))orig_ws_receiveMessage)(self, _cmd, wrappedCompletion);
}

static void mfInstallWebSocketHooks(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class wsTask = NSClassFromString(@"NSURLSessionWebSocketTask");
        if (!wsTask) { mfLog(@"WS hooks: NSURLSessionWebSocketTask not found (iOS < 15)"); return; }
        Method m = class_getInstanceMethod(wsTask, NSSelectorFromString(@"sendMessage:completionHandler:"));
        if (m) { orig_ws_sendMessage = method_getImplementation(m); method_setImplementation(m, (IMP)new_ws_sendMessage); }
        m = class_getInstanceMethod(wsTask, NSSelectorFromString(@"receiveMessageWithCompletionHandler:"));
        if (m) { orig_ws_receiveMessage = method_getImplementation(m); method_setImplementation(m, (IMP)new_ws_receiveMessage); }
        mfLog(@"WS hooks installed (NSURLSessionWebSocketTask)");
    });
}

// ====== 注册/注销 NSURLProtocol ======
// swizzle NSURLSessionConfiguration.protocolClasses——所有新建 session 都带上 MFURLProtocol
static IMP orig_protocolClasses;
static NSArray *new_protocolClasses(id self, SEL _cmd) {
    NSArray *orig = ((NSArray *(*)(id, SEL))orig_protocolClasses)(self, _cmd);
    NSMutableArray *arr = [orig mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:[MFURLProtocol class]]) {
        [arr insertObject:[MFURLProtocol class] atIndex:0];
    }
    return arr;
}

static void mfInstallNetworkCaptureOnce(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        [NSURLProtocol registerClass:[MFURLProtocol class]];
        // swizzle protocolClasses——拦截所有 NSURLSession
        Class cfgCls = NSClassFromString(@"NSURLSessionConfiguration");
        if (cfgCls) {
            Method m = class_getInstanceMethod(cfgCls, @selector(protocolClasses));
            if (m) {
                orig_protocolClasses = method_getImplementation(m);
                method_setImplementation(m, (IMP)new_protocolClasses);
                mfLog(@"NetworkCapture: protocolClasses swizzled");
            }
        }
        mfLog(@"NetworkCapture: NSURLProtocol registered");
    });
}

void mfInstallNetworkCapture(void) {
    mfInstallNetworkCaptureOnce();
    mfInstallWebSocketHooks();
}

// ====== 捕获列表页面（子页展示） ======
static void mfExpandCardForPage(void) {
    // 子页创建前先拉长卡片——让滚动视图等基于 g_mfCardH 的布局用大高度
    if (g_mfPanelOverlay) {
        CGFloat maxH = MIN(560, g_mfPanelOverlay.bounds.size.height - 100);
        if (g_mfCardH < maxH) mfSetCardHeight(maxH);
    }
}
static NSString *mfDisplayDict(NSDictionary *d) {
    if (!d || d.count == 0) return @"(空)";
    NSMutableString *s = [NSMutableString string];
    for (NSString *k in d) [s appendFormat:@"%@: %@\n", k, d[k]];
    return s;
}
static NSString *mfDisplayData(NSData *data) {
    if (!data || data.length == 0) return @"(空)";
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!s) return [NSString stringWithFormat:@"<二进制 %lu 字节>", (unsigned long)data.length];
    return s;
}

// 详情页——完整展示请求/响应 headers/body，可复制
void mfShowCaptureDetailPage(MFNetRecord *rec) {
    if (!rec) return;
    mfExpandCardForPage();
    UIView *page = mfMakePage(@"请求详情", YES);

    // 复制/改响应已移至列表左滑操作
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
    CGFloat y = 8;

    // 概览
    NSString *summary = [NSString stringWithFormat:@"%@ %ld  %@",
        rec.method ?: @"?", (long)rec.status, rec.url ?: @"?"];
    UILabel *sumLb = [UILabel new];
    sumLb.font = [UIFont systemFontOfSize:12];
    sumLb.textColor = [UIColor labelColor];
    sumLb.numberOfLines = 0;
    sumLb.frame = CGRectMake(12, y, g_mfCardW - 24, 46);
    sumLb.text = summary;
    [sv addSubview:sumLb];
    y += 52;

    // Section
    NSArray *sectionTitles = @[@"请求 Headers", @"请求 Body", @"响应 Headers", @"响应 Body"];
    NSArray *sectionValues = @[
        mfDisplayDict(rec.reqHeaders),
        mfDisplayData(rec.reqBody),
        mfDisplayDict(rec.respHeaders),
        mfDisplayData(rec.respBody),
    ];
    for (NSUInteger i = 0; i < sectionTitles.count; i++) {
        UILabel *t = [UILabel new];
        t.font = [UIFont boldSystemFontOfSize:12];
        t.textColor = [UIColor systemBlueColor];
        t.frame = CGRectMake(12, y, g_mfCardW - 24, 22);
        t.text = sectionTitles[i];
        [sv addSubview:t];
        y += 24;

        UILabel *v = [UILabel new];
        v.font = [UIFont systemFontOfSize:11];
        v.textColor = [UIColor secondaryLabelColor];
        v.numberOfLines = 0;
        NSString *val = sectionValues[i];
        CGSize size = [val boundingRectWithSize:CGSizeMake(g_mfCardW - 24, CGFLOAT_MAX)
            options:NSStringDrawingUsesLineFragmentOrigin
            attributes:@{NSFontAttributeName: v.font} context:nil].size;
        v.frame = CGRectMake(12, y, g_mfCardW - 24, size.height + 4);
        v.text = val;
        [sv addSubview:v];
        y += size.height + 12;
    }

    sv.contentSize = CGSizeMake(g_mfCardW, y + 16);
    [page addSubview:sv];
    mfPushPage(page);
}

// ====== 捕获列表控制器（UITableView + 左滑操作） ======
@interface MFCaptureList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *records;
@end
@implementation MFCaptureList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return (NSInteger)self.records.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *id_ = @"mfcaprow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:id_];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:id_];
    MFNetRecord *rec = self.records[ip.row];
    NSString *u = rec.url.length > 64 ? [rec.url substringToIndex:64] : rec.url;
    c.textLabel.text = u;
    c.textLabel.font = [UIFont systemFontOfSize:11];
    c.textLabel.textColor = [UIColor systemBlueColor];
    c.detailTextLabel.text = [NSString stringWithFormat:@"%@ %ld | %@", rec.method ?: @"?", (long)rec.status, rec.summary ?: @""];
    c.detailTextLabel.font = [UIFont systemFontOfSize:10];
    c.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    c.backgroundColor = UIColor.clearColor;
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    mfShowCaptureDetailPage(self.records[ip.row]);
}
// 左滑操作：改响应 / 复制（对标系统邮件式 swipe actions）
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    MFNetRecord *rec = self.records[ip.row];
    __block UIButton *synthetic = [UIButton buttonWithType:UIButtonTypeSystem]; // 复用 Ctrl 取参通道
    objc_setAssociatedObject(synthetic, "rec", rec, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    UIContextualAction *mod = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"改响应" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            objc_setAssociatedObject(g_mfCtrl, "mfSwipeRec", rec, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            [(id)g_mfCtrl performSelector:NSSelectorFromString(@"mfModifyResponseFromSwipe")];
            done(YES);
        }];
    mod.backgroundColor = [UIColor systemOrangeColor];

    UIContextualAction *copy = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"复制" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            objc_setAssociatedObject(g_mfCtrl, "mfSwipeRec", rec, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            [(id)g_mfCtrl performSelector:NSSelectorFromString(@"mfCopyRecordFromSwipe")];
            done(YES);
        }];
    copy.backgroundColor = [UIColor systemBlueColor];

    return [UISwipeActionsConfiguration configurationWithActions:@[copy, mod]];
}
@end

void mfShowNetworkCapturePage(void) {
    mfExpandCardForPage();
    UIView *page = mfMakePage(@"📡 网络捕获", YES);

    UITableView *tb = [[UITableView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42) style:UITableViewStylePlain];
    tb.backgroundColor = UIColor.clearColor;
    tb.rowHeight = 58;

    MFCaptureList *ctl = [MFCaptureList new];
    @synchronized (g_capturedRecords) {
        ctl.records = g_capturedRecords ? [g_capturedRecords copy] : @[];
    }
    tb.dataSource = ctl; tb.delegate = ctl;
    objc_setAssociatedObject(page, "ctl", ctl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    if (!ctl.records.count) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 60, g_mfCardW - 32, 60)];
        e.text = @"暂无捕获记录\n到「网络分析」打开实时捕获开关";
        e.numberOfLines = 0;
        e.textAlignment = NSTextAlignmentCenter;
        e.font = [UIFont systemFontOfSize:13];
        e.textColor = [UIColor secondaryLabelColor];
        e.userInteractionEnabled = NO;
        [tb addSubview:e];
    }

    [page addSubview:tb];
    mfPushPage(page);
}
// ====== 数据分析页（7 宫格——解密捕获已迁网络分析 v1.9.3） ======
void mfShowDataAnalysisPage(void) {
    UIView *page = mfMakePage(@"数据分析", YES);
    CGFloat gw = (g_mfCardW - 32 - 12) / 2;
    CGFloat gy = 48;
    gy = mfGridButton(page, 16, gy, gw, @"网络分析", @"🌐", @selector(mfShowNetAnalyzerPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"解密工具", @"🔐", @selector(mfShowCryptoPage), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"ObjC 规则", @"🔧", @selector(mfShowMethodTracePage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"ClassDump", @"📦", @selector(mfShowClassDumpPage), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"Keychain 管理", @"🔑", @selector(mfShowKeychainManagerPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"MachO 深检", @"🔬", @selector(mfShowMachODeepPage), NO, nil);   // v2.7.1: 回归右列，网格对称
    // v2.6.21: 实时日志/电池详情 提升到主页
    mfPushPage(page);
}

// ====== CryptoToolbox 页面 ======
// 解密工具箱 v2 已迁移至 MFCryptoToolbox.m

// ====== 规则编辑页（新建/编辑共用） ======
// 对标 ToolsEric UCPTURLRuleEditorViewController 102 方法：
// 四象限编辑(reqHeaders/respHeaders/reqBody/respBody) + direction segment + reject 开关
// index<0 新建；>=0 编辑 g_rewriteRules[index]
// ====== 规则编辑页（新建/编辑共用） ======
// 对标 ToolsEric UCPTURLRuleEditorViewController 102 方法：
// 四象限编辑(reqHeaders/respHeaders/reqBody/respBody) + direction segment + reject 开关
// index<0 新建；>=0 编辑 g_rewriteRules[index]
static void mfShowRuleEditPageImpl(NSString *pattern, NSString *action, NSInteger index, BOOL fromList) {
    mfLoadRules();
    MFRewriteRule *editRule = nil;
    if (index >= 0 && index < (NSInteger)g_rewriteRules.count) editRule = g_rewriteRules[index];
    
    UIView *page = mfMakePage(index < 0 ? @"新建规则" : @"编辑规则", YES);
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
    CGFloat y = 12;

    // 预填
    NSString *initPattern = editRule.pattern ?: pattern ?: @"";
    NSString *initMatch = editRule.matchType ?: @"contain";
    NSString *initAction = editRule.action ?: (action ?: @"replaceResp");
    NSString *initUrlRepl = editRule.urlReplace ?: @"";
    NSString *initName = editRule.name ?: @"";
    NSString *initDir = editRule.direction ?: @"";
    BOOL initReject = editRule.reject;
    NSDictionary *initReqH = editRule.reqHeaders ?: @{};
    NSDictionary *initRespH = editRule.respHeaders ?: @{};
    NSString *initReqB = editRule.reqBody ?: @"";
    NSString *initRespB = editRule.respBody ?: @"";

    // 规则名称
    UILabel *nLabel = [UILabel new];
    nLabel.frame = CGRectMake(16, y, 100, 22);
    nLabel.text = @"规则名称";
    nLabel.font = [UIFont systemFontOfSize:13];
    nLabel.textColor = [UIColor secondaryLabelColor];
    [sv addSubview:nLabel];
    UITextField *nameField = [[UITextField alloc] initWithFrame:CGRectMake(16, y + 24, g_mfCardW - 32, 40)];
    nameField.placeholder = @"可选，方便识别";
    nameField.text = initName;
    nameField.font = [UIFont systemFontOfSize:13];
    nameField.borderStyle = UITextBorderStyleRoundedRect;
    nameField.clearButtonMode = UITextFieldViewModeWhileEditing;
    nameField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    mfAttachKbBar(nameField);   // v2.7.1: 键盘收起工具条
    [sv addSubview:nameField];
    y += 72;

    // 匹配方式分段
    UILabel *mLabel = [UILabel new];
    mLabel.frame = CGRectMake(16, y, 100, 22);
    mLabel.text = @"匹配方式";
    mLabel.font = [UIFont systemFontOfSize:13];
    mLabel.textColor = [UIColor secondaryLabelColor];
    [sv addSubview:mLabel];
    UISegmentedControl *matchSeg = [[UISegmentedControl alloc] initWithItems:@[@"包含", @"精确", @"正则"]];
    matchSeg.frame = CGRectMake(16, y + 24, g_mfCardW - 32, 32);
    matchSeg.selectedSegmentIndex = [initMatch isEqualToString:@"url"] ? 1 : ([initMatch isEqualToString:@"regex"] ? 2 : 0);
    [sv addSubview:matchSeg];
    y += 64;

    // 匹配内容输入框
    UITextField *patField = [[UITextField alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 40)];
    patField.placeholder = @"匹配的 URL（含域名即可）";
    patField.text = initPattern;
    patField.font = [UIFont systemFontOfSize:13];
    patField.borderStyle = UITextBorderStyleRoundedRect;
    patField.clearButtonMode = UITextFieldViewModeWhileEditing;
    patField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    patField.autocorrectionType = UITextAutocorrectionTypeNo;
    patField.keyboardType = UIKeyboardTypeURL;
    mfAttachKbBar(patField);   // v2.7.1: 键盘收起工具条
    [sv addSubview:patField];
    y += 48;

    // Direction segment: 请求 / 响应 / 双向
    UILabel *dLabel = [UILabel new];
    dLabel.frame = CGRectMake(16, y, 100, 22);
    dLabel.text = @"方向";
    dLabel.font = [UIFont systemFontOfSize:13];
    dLabel.textColor = [UIColor secondaryLabelColor];
    [sv addSubview:dLabel];
    UISegmentedControl *dirSeg = [[UISegmentedControl alloc] initWithItems:@[@"双向", @"请求", @"响应"]];
    dirSeg.frame = CGRectMake(16, y + 24, g_mfCardW - 32, 32);
    dirSeg.selectedSegmentIndex = [initDir isEqualToString:@"request"] ? 1 : ([initDir isEqualToString:@"response"] ? 2 : 0);
    [sv addSubview:dirSeg];
    y += 64;

    // Reject switch
    UISwitch *rejectSw = [[UISwitch alloc] initWithFrame:CGRectMake(16, y + 4, 51, 31)];
    rejectSw.on = initReject;
    [sv addSubview:rejectSw];
    UILabel *rjLabel = [UILabel new];
    rjLabel.frame = CGRectMake(75, y + 4, 200, 31);
    rjLabel.text = @"拒绝/屏蔽 (reject)";
    rjLabel.font = [UIFont systemFontOfSize:13];
    [sv addSubview:rjLabel];
    y += 44;

    // 四象限编辑区（ScrollView 嵌套）
    UIScrollView *quadSv = [[UIScrollView alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 280)];
    quadSv.backgroundColor = [UIColor secondarySystemBackgroundColor];
    quadSv.layer.cornerRadius = 8;
    quadSv.clipsToBounds = YES;
    [sv addSubview:quadSv];
    CGFloat qy = 8;

    // reqHeaders
    UILabel *l1 = [UILabel new];
    l1.frame = CGRectMake(8, qy, 120, 20);
    l1.text = @"请求 Headers (JSON)";
    l1.font = [UIFont systemFontOfSize:11];
    l1.textColor = [UIColor systemBlueColor];
    [quadSv addSubview:l1];
    qy += 22;
    UITextView *reqHView = [[UITextView alloc] initWithFrame:CGRectMake(8, qy, g_mfCardW - 48, 90)];
    reqHView.text = initReqH.count ? [initReqH description] : @"{}";
    reqHView.font = [UIFont systemFontOfSize:11];
    reqHView.layer.borderWidth = 0.5;
    reqHView.layer.borderColor = [UIColor systemGray3Color].CGColor;
    reqHView.layer.cornerRadius = 6;
    reqHView.backgroundColor = [UIColor systemBackgroundColor];
    reqHView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    reqHView.autocorrectionType = UITextAutocorrectionTypeNo;
    mfAttachKbBar(reqHView);   // v2.7.1: 键盘收起工具条
    [quadSv addSubview:reqHView];
    qy += 98;

    // respHeaders
    UILabel *l2 = [UILabel new];
    l2.frame = CGRectMake(8, qy, 120, 20);
    l2.text = @"响应 Headers (JSON)";
    l2.font = [UIFont systemFontOfSize:11];
    l2.textColor = [UIColor systemBlueColor];
    [quadSv addSubview:l2];
    qy += 22;
    UITextView *respHView = [[UITextView alloc] initWithFrame:CGRectMake(8, qy, g_mfCardW - 48, 90)];
    respHView.text = initRespH.count ? [initRespH description] : @"{}";
    respHView.font = [UIFont systemFontOfSize:11];
    respHView.layer.borderWidth = 0.5;
    respHView.layer.borderColor = [UIColor systemGray3Color].CGColor;
    respHView.layer.cornerRadius = 6;
    respHView.backgroundColor = [UIColor systemBackgroundColor];
    respHView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    respHView.autocorrectionType = UITextAutocorrectionTypeNo;
    mfAttachKbBar(respHView);   // v2.7.1: 键盘收起工具条
    [quadSv addSubview:respHView];
    qy += 98;

    // reqBody
    UILabel *l3 = [UILabel new];
    l3.frame = CGRectMake(8, qy, 120, 20);
    l3.text = @"请求 Body";
    l3.font = [UIFont systemFontOfSize:11];
    l3.textColor = [UIColor systemBlueColor];
    [quadSv addSubview:l3];
    qy += 22;
    UITextView *reqBView = [[UITextView alloc] initWithFrame:CGRectMake(8, qy, g_mfCardW - 48, 90)];
    reqBView.text = initReqB;
    reqBView.font = [UIFont systemFontOfSize:11];
    reqBView.layer.borderWidth = 0.5;
    reqBView.layer.borderColor = [UIColor systemGray3Color].CGColor;
    reqBView.layer.cornerRadius = 6;
    reqBView.backgroundColor = [UIColor systemBackgroundColor];
    reqBView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    reqBView.autocorrectionType = UITextAutocorrectionTypeNo;
    mfAttachKbBar(reqBView);   // v2.7.1: 键盘收起工具条
    [quadSv addSubview:reqBView];
    qy += 98;

    // respBody
    UILabel *l4 = [UILabel new];
    l4.frame = CGRectMake(8, qy, 120, 20);
    l4.text = @"响应 Body";
    l4.font = [UIFont systemFontOfSize:11];
    l4.textColor = [UIColor systemBlueColor];
    [quadSv addSubview:l4];
    qy += 22;
    UITextView *respBView = [[UITextView alloc] initWithFrame:CGRectMake(8, qy, g_mfCardW - 48, 90)];
    respBView.text = initRespB;
    respBView.font = [UIFont systemFontOfSize:11];
    respBView.layer.borderWidth = 0.5;
    respBView.layer.borderColor = [UIColor systemGray3Color].CGColor;
    respBView.layer.cornerRadius = 6;
    respBView.backgroundColor = [UIColor systemBackgroundColor];
    respBView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    respBView.autocorrectionType = UITextAutocorrectionTypeNo;
    mfAttachKbBar(respBView);   // v2.7.1: 键盘收起工具条
    [quadSv addSubview:respBView];
    qy += 98;

    quadSv.contentSize = CGSizeMake(g_mfCardW - 32, qy + 8);
    y += 288;

    // 保存按钮
    UIButton *saveBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    saveBtn.frame = CGRectMake(16, y + 4, g_mfCardW - 32, 40);
    saveBtn.backgroundColor = [UIColor systemBlueColor];
    saveBtn.layer.cornerRadius = 10;
    [saveBtn setTitle:@"保存规则" forState:UIControlStateNormal];
    [saveBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [saveBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfSaveRuleFromEditor:") forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:saveBtn];
    y += 56;

    sv.contentSize = CGSizeMake(g_mfCardW, y + 20);
    [page addSubview:sv];

    // 保存按钮回调所需上下文
    objc_setAssociatedObject(saveBtn, "seg", matchSeg, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "seg2", dirSeg, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "rsw", rejectSw, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "f1", patField, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "f2", nameField, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "tv1", reqHView, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "tv2", respHView, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "tv3", reqBView, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "tv4", respBView, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "idx", @(index), OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "fromList", @(fromList), OBJC_ASSOCIATION_RETAIN);

    mfPushPage(page);
}

// 对外入口：详情页"改响应"→ 预填当前记录 URL（fromList=NO，保存后回详情）；
// 列表页添加/编辑（fromList=YES，保存后刷新列表）
void mfShowRuleEditPage(NSString *pattern, NSString *action, NSInteger index, BOOL fromList) {
    mfLoadRules();
    mfShowRuleEditPageImpl(pattern, action, index, fromList);
}

// ====== 网络修改页（当前 app 的规则列表 + 开关） ======
void mfShowNetworkModifyPage(void) {
    UIView *page = mfMakePage(@"网络修改", YES);
    mfLoadRules();
    // 开关
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(16, 48, 60, 31)];
    sw.on = g_rewriteEnabled;
    [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfRewriteSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [page addSubview:sw];
    UILabel *swLb = [[UILabel alloc] initWithFrame:CGRectMake(84, 52, 220, 24)];
    swLb.text = @"启用拦截修改";
    swLb.font = [UIFont systemFontOfSize:14];
    [page addSubview:swLb];
    UILabel *scopeLb = [[UILabel alloc] initWithFrame:CGRectMake(84, 74, g_mfCardW - 100, 16)];
    scopeLb.text = [NSString stringWithFormat:@"仅作用于：%@", mfCurrentBundleId()];
    scopeLb.font = [UIFont systemFontOfSize:10];
    scopeLb.textColor = [UIColor tertiaryLabelColor];
    [page addSubview:scopeLb];

    // 规则列表（只显示当前 app 的规则）
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 96, g_mfCardW, g_mfCardH - 96)];
    CGFloat y = 8;
    NSMutableArray *myRules = [NSMutableArray new];
    for (MFRewriteRule *r in g_rewriteRules) {
        if (r.appBundle.length == 0 || [r.appBundle isEqualToString:mfCurrentBundleId()]) [myRules addObject:r];
    }
    if (myRules.count == 0) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 20, g_mfCardW - 32, 40)];
        e.text = @"暂无规则\n可在捕获详情页点「改响应」快速添加";
        e.numberOfLines = 0;
        e.textAlignment = NSTextAlignmentCenter;
        e.textColor = [UIColor secondaryLabelColor];
        e.font = [UIFont systemFontOfSize:13];
        [sv addSubview:e];
    } else {
        for (MFRewriteRule *rule in myRules) {
            NSInteger idx = [g_rewriteRules indexOfObject:rule];
            UIView *row = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 76)];
            row.backgroundColor = [UIColor secondarySystemBackgroundColor];
            row.layer.cornerRadius = 10;
            CGFloat rightX = row.bounds.size.width - 8;
            // 左侧：name + pattern + 信息
            CGFloat leftW = rightX - 110;
            UILabel *nameLb = nil;
            if (rule.name.length > 0) {
                nameLb = [[UILabel alloc] initWithFrame:CGRectMake(10, 4, leftW, 18)];
                nameLb.font = [UIFont boldSystemFontOfSize:11];
                nameLb.textColor = rule.enabled ? [UIColor labelColor] : [UIColor secondaryLabelColor];
                nameLb.text = rule.name;
                [row addSubview:nameLb];
            }
            UILabel *pat = [[UILabel alloc] initWithFrame:CGRectMake(10, nameLb ? 22 : 6, leftW, 18)];
            pat.font = [UIFont systemFontOfSize:10];
            pat.textColor = rule.enabled ? [UIColor systemBlueColor] : [UIColor secondaryLabelColor];
            pat.text = rule.pattern;
            [row addSubview:pat];
            // 详细信息：matchType | direction | reject | action
            NSString *dirStr = rule.direction.length ? rule.direction : @"双向";
            NSString *actName = rule.reject ? @"屏蔽" :
                ([rule.action isEqualToString:@"replaceReq"] ? @"替换请求" : @"替换响应");
            NSString *detail = [NSString stringWithFormat:@"%@ | %@ | %@", rule.matchType, dirStr, actName];
            if (rule.reject) detail = [detail stringByAppendingString:@" ⛔"];
            UILabel *act = [[UILabel alloc] initWithFrame:CGRectMake(10, nameLb ? 40 : 28, leftW, 20)];
            act.font = [UIFont systemFontOfSize:9];
            act.textColor = [UIColor tertiaryLabelColor];
            act.text = detail;
            [row addSubview:act];
            // 右侧：开关（上）+ 编辑/删除（下）
            UISwitch *rsw = [[UISwitch alloc] initWithFrame:CGRectMake(rightX - 51, 4, 51, 31)];
            rsw.on = rule.enabled;
            objc_setAssociatedObject(rsw, "idx", @(idx), OBJC_ASSOCIATION_RETAIN);
            [rsw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfRuleSwitchChanged:") forControlEvents:UIControlEventValueChanged];
            [row addSubview:rsw];
            UIButton *editBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            editBtn.frame = CGRectMake(rightX - 80, 40, 36, 20);
            [editBtn setTitle:@"编辑" forState:UIControlStateNormal];
            editBtn.titleLabel.font = [UIFont systemFontOfSize:11];
            objc_setAssociatedObject(editBtn, "idx", @(idx), OBJC_ASSOCIATION_RETAIN);
            [editBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfEditRuleTapped:") forControlEvents:UIControlEventTouchUpInside];
            [row addSubview:editBtn];
            UIButton *delBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            delBtn.frame = CGRectMake(rightX - 40, 40, 32, 20);
            [delBtn setTitle:@"删除" forState:UIControlStateNormal];
            delBtn.titleLabel.font = [UIFont systemFontOfSize:11];
            [delBtn setTitleColor:[UIColor systemRedColor] forState:UIControlStateNormal];
            objc_setAssociatedObject(delBtn, "idx", @(idx), OBJC_ASSOCIATION_RETAIN);
            [delBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDeleteRuleTapped:") forControlEvents:UIControlEventTouchUpInside];
            [row addSubview:delBtn];
            [sv addSubview:row];
            y += 82;
        }
    }
    // 🔧 ObjC 规则入口(精确 hook, 与网络规则统一范式) — 取代已废除的方法监控
    mfRowButton(sv, 12, y + 4, g_mfCardW - 24, 38, @"🔧 管理 ObjC 方法 Hook 规则", [UIColor systemIndigoColor], NSSelectorFromString(@"mfShowMethodTracePage"));
    y += 46;
    // 添加规则按钮
    mfRowButton(sv, 12, y + 4, g_mfCardW - 24, 38, @"+ 添加规则", [UIColor systemBlueColor], NSSelectorFromString(@"mfAddRuleTapped"));
    y += 46;
    sv.contentSize = CGSizeMake(g_mfCardW, y + 16);
    [page addSubview:sv];
    mfPushPage(page);
}

// ====== 规则管理页（UITableView + 左滑操作，对标捕获列表） ======
@interface MFRuleManagerList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *rules;
@end
@implementation MFRuleManagerList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return (NSInteger)self.rules.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *id_ = @"mfruletrow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:id_];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:id_];
    MFRewriteRule *rule = self.rules[ip.row];
    // 主标题：name 或 pattern
    c.textLabel.text = rule.name.length ? rule.name : rule.pattern;
    c.textLabel.font = [UIFont systemFontOfSize:12];
    c.textLabel.textColor = rule.enabled ? [UIColor labelColor] : [UIColor secondaryLabelColor];
    // 副标题：matchType | direction | action
    NSString *dirStr = rule.direction.length ? rule.direction : @"双向";
    NSString *actName = rule.reject ? @"屏蔽" :
        ([rule.action isEqualToString:@"replaceReq"] ? @"替换请求" : @"替换响应");
    NSString *detail = [NSString stringWithFormat:@"%@ | %@ | %@", rule.matchType, dirStr, actName];
    if (rule.reject) detail = [detail stringByAppendingString:@" ⛔"];
    c.detailTextLabel.text = detail;
    c.detailTextLabel.font = [UIFont systemFontOfSize:10];
    c.detailTextLabel.textColor = [UIColor tertiaryLabelColor];
    c.backgroundColor = UIColor.clearColor;
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    // 点击行直接编辑
    MFRewriteRule *rule = self.rules[ip.row];
    NSInteger idx = [g_rewriteRules indexOfObject:rule];
    mfShowRuleEditPage(nil, nil, idx, YES);
}
// 左滑操作：启用/禁用、编辑、删除
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    MFRewriteRule *rule = self.rules[ip.row];
    NSInteger idx = [g_rewriteRules indexOfObject:rule];
    __block UIButton *synthetic = [UIButton buttonWithType:UIButtonTypeSystem];
    objc_setAssociatedObject(synthetic, "idx", @(idx), OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    // 启用/禁用
    UIContextualAction *toggle = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:rule.enabled ? @"禁用" : @"启用" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            rule.enabled = !rule.enabled;
            mfSaveRule(rule, idx);
            mfToast(rule.enabled ? @"✅ 已启用" : @"⏸️ 已禁用");
            [tv reloadRowsAtIndexPaths:@[ip] withRowAnimation:UITableViewRowAnimationNone];
            done(YES);
        }];
    toggle.backgroundColor = rule.enabled ? [UIColor systemOrangeColor] : [UIColor systemGreenColor];

    // 编辑
    UIContextualAction *edit = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"编辑" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            mfShowRuleEditPage(nil, nil, idx, YES);
            done(YES);
        }];
    edit.backgroundColor = [UIColor systemBlueColor];

    // 删除
    UIContextualAction *del = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleDestructive
        title:@"删除" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"删除规则"
                message:[NSString stringWithFormat:@"确定删除这条规则？\n%@", rule.pattern]
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"删除" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
                mfRemoveRule(idx);
                mfToast(@"🗑️ 已删除");
            }]];
            [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
            [g_mfPanelRootVC presentViewController:alert animated:YES completion:nil];
            done(YES);
        }];
    del.backgroundColor = [UIColor systemRedColor];

    return [UISwipeActionsConfiguration configurationWithActions:@[del, edit, toggle]];
}
@end

// 规则管理页面入口（网络分析页调用）
void mfShowRuleManagerPage(void) {
    mfLoadRules();
    mfExpandCardForPage();
    UIView *page = mfMakePage(@"🔧 规则管理", YES);
    // 说明：有规则即生效，无全局开关
    UILabel *note = [[UILabel alloc] initWithFrame:CGRectMake(16, 44, g_mfCardW - 32, 30)];
    note.font = [UIFont systemFontOfSize:11];
    note.textColor = [UIColor tertiaryLabelColor];
    note.numberOfLines = 2;
    note.text = @"有规则即生效（仅作用于当前 App：%@）\n左滑：删除 / 编辑 / 启用禁用";
    note.text = [NSString stringWithFormat:note.text, mfCurrentBundleId()];
    [page addSubview:note];

    // 筛选当前 app 的规则
    NSMutableArray *myRules = [NSMutableArray new];
    for (MFRewriteRule *r in g_rewriteRules) {
        if (r.appBundle.length == 0 || [r.appBundle isEqualToString:mfCurrentBundleId()]) [myRules addObject:r];
    }

    // UITableView
    UITableView *tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 80, g_mfCardW, g_mfCardH - 80) style:UITableViewStylePlain];
    tv.backgroundColor = UIColor.clearColor;
    tv.separatorStyle = UITableViewCellSeparatorStyleNone;
    tv.rowHeight = 64;
    MFRuleManagerList *dataSource = [MFRuleManagerList new];
    dataSource.rules = myRules;
    tv.dataSource = dataSource;
    tv.delegate = dataSource;
    objc_setAssociatedObject(page, "mfRuleDataSource", dataSource, OBJC_ASSOCIATION_RETAIN);
    [page addSubview:tv];

    // 添加规则按钮（固定在底部）
    mfRowButton(page, 12, g_mfCardH - 108, g_mfCardW - 24, 40, @"🔧 管理 ObjC 方法 Hook 规则", [UIColor systemIndigoColor], NSSelectorFromString(@"mfShowMethodTracePage"));

    mfRowButton(page, 12, g_mfCardH - 60, g_mfCardW - 24, 40, @"+ 添加规则", [UIColor systemBlueColor], NSSelectorFromString(@"mfAddRuleTapped"));

    mfPushPage(page);
}
