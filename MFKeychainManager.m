// MFKeychainManager.m — Keychain 可视化/备份/恢复模块
// 面板页实现 (类似 Product 页)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CloudKit/CloudKit.h>
#import <dlfcn.h>
#import <sys/mman.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <errno.h>
#import <string.h>
#import <objc/message.h>
#import "fishhook.h"
#import "MFPanel.h"
#import "LSApplicationProxy.h"

// SecTask 私有 API 声明 (Security framework 内，iOS 未公开头文件)
typedef struct CF_BRIDGED_TYPE(id) OpaqueSecTaskRef *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef entitlement, CFErrorRef *error);

extern UIViewController *g_mfPanelRootVC;
extern void mfLog(NSString *fmt, ...);  // 使用面板统一日志

// ====== 工具函数 ======
#define MFKEYCHAIN_VERSION @"1.5.0"

static void mfKLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    mfLog(@"[MFKeychain v%@] %@", MFKEYCHAIN_VERSION, msg);
}

static NSArray *mfGetKeychainItems(void) {
    mfKLog(@"mfGetKeychainItems called");
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    mfKLog(@"SecItemCopyMatching status=%d", (int)status);
    if (status == errSecItemNotFound) {
        mfKLog(@"no items found");
        return @[];
    }
    if (status != errSecSuccess) {
        mfKLog(@"SecItemCopyMatching failed: %d", (int)status);
        return @[];
    }
    NSArray *items = (__bridge_transfer NSArray *)result;
    mfKLog(@"found %lu items", (unsigned long)(items ? items.count : 0));
    return items ?: @[];
}

static void mfPresentOnPanelVC(UIAlertController *alert) {
    mfKLog(@"mfPresentOnPanelVC called, g_mfPanelRootVC=%p", g_mfPanelRootVC);
    if (g_mfPanelRootVC) {
        [g_mfPanelRootVC presentViewController:alert animated:YES completion:nil];
    } else {
        mfKLog(@"ERROR: g_mfPanelRootVC is nil, cannot present");
    }
}

// 删除单个 Keychain 项 (静态内部函数)
static BOOL mfDeleteKeychainItemInternal(NSDictionary *item);
static void mfRefreshKeychainListIfVisible(void);
// 详情页前置声明（列表控制器的左滑「编辑」要用）
static void mfShowKeychainDetailMode(NSDictionary *item, BOOL autoEdit);
static void mfKeychainEnterEdit(UIButton *btn);
static void mfKeychainSaveEdit(UIButton *btn);

static BOOL mfDeleteKeychainItemInternal(NSDictionary *item) {
    mfKLog(@"mfDeleteKeychainItemInternal called for account=%@", item[(__bridge id)kSecAttrAccount] ?: @"(nil)");
    NSDictionary *deleteQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: item[(__bridge id)kSecAttrAccount] ?: @"",
        (__bridge id)kSecAttrService: item[(__bridge id)kSecAttrService] ?: @""
    };
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
    mfKLog(@"SecItemDelete status=%d", (int)status);
    return status == errSecSuccess || status == errSecItemNotFound;
}

// ====== 核心操作 (在后台线程执行) ======

// 导出 Keychain -> Base64 JSON -> 粘贴板（提示全部用浮层 toast，不用弹窗）
static void mfCopyKeychainInBackground(void) {
    mfKLog(@"mfCopyKeychainInBackground START");
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        mfKLog(@"background queue: fetching items");
        NSArray *items = mfGetKeychainItems();
        if (items.count == 0) {
            mfKLog(@"no items to copy");
            dispatch_async(dispatch_get_main_queue(), ^{ mfToast(@"⚠️ 无 Keychain 项可导出"); });
            return;
        }
        
        mfKLog(@"building export array for %lu items", (unsigned long)items.count);
        NSMutableArray *exportArray = [NSMutableArray array];
        for (NSDictionary *item in items) {
            NSMutableDictionary *exp = [NSMutableDictionary dictionary];
            NSData *data = item[(__bridge id)kSecValueData];
            if (data) exp[@"data"] = [data base64EncodedStringWithOptions:0];
            for (id key in item) {
                if (![key isEqual:(__bridge id)kSecValueData]) {
                    id val = item[key];
                    // 只保留 JSON 可序列化类型：NSString, NSNumber, NSArray, NSDictionary, NSNull
                    // 其他类型 (NSDate, NSData 等) 转字符串
                    if ([val isKindOfClass:[NSString class]] ||
                        [val isKindOfClass:[NSNumber class]] ||
                        [val isKindOfClass:[NSArray class]] ||
                        [val isKindOfClass:[NSDictionary class]] ||
                        [val isKindOfClass:[NSNull class]]) {
                        exp[key] = val;
                    } else {
                        exp[key] = [val description];
                    }
                }
            }
            [exportArray addObject:exp];
        }
        
        mfKLog(@"serializing JSON");
        @try {
            NSError *err = nil;
            NSData *jsonData = [NSJSONSerialization dataWithJSONObject:exportArray options:NSJSONWritingPrettyPrinted error:&err];
            if (err || !jsonData) {
                mfKLog(@"JSON encode failed: %@", err);
                @throw [NSException exceptionWithName:@"JSONEncodeError" reason:[err ?: @"" description] userInfo:nil];
            }
            
            mfKLog(@"JSON size: %lu bytes", (unsigned long)jsonData.length);
            NSString *base64 = [jsonData base64EncodedStringWithOptions:0];
            mfKLog(@"Base64 length: %lu", (unsigned long)base64.length);
            
            [[UIPasteboard generalPasteboard] setString:base64];
            mfKLog(@"copied to pasteboard");
            
            dispatch_async(dispatch_get_main_queue(), ^{
                mfKLog(@"copy done -> toast");
                mfToast([NSString stringWithFormat:@"✅ 已复制到剪贴板 (%lu 项, %lu 字符)", (unsigned long)items.count, (unsigned long)base64.length]);
            });
        } @catch (NSException *e) {
            mfKLog(@"JSON serialization exception: %@", e);
            dispatch_async(dispatch_get_main_queue(), ^{ mfToast([NSString stringWithFormat:@"❌ 导出失败: %@", e.reason ?: @""]); });
        }
    });
    mfKLog(@"mfCopyKeychainInBackground END (async)");
}

// 单个项目恢复处理（前向声明）
static void mfProcessSingleRestoreItem(NSDictionary *item);

// 从粘贴板导入恢复 Keychain
static void mfRestoreKeychainInBackground(NSString *base64) {
    mfKLog(@"mfRestoreKeychainInBackground START, input length=%lu", (unsigned long)(base64 ? base64.length : 0));
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        mfKLog(@"background queue: processing restore");
        if (!base64 || base64.length == 0) {
            mfKLog(@"ERROR: empty base64 input");
            dispatch_async(dispatch_get_main_queue(), ^{ mfToast(@"❌ 输入为空"); });
            return;
        }
        
        NSData *jsonData = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
        if (!jsonData) {
            mfKLog(@"Base64 decode failed, first 50 chars: %@", [base64 substringToIndex:MIN(50, base64.length)]);
            dispatch_async(dispatch_get_main_queue(), ^{ mfToast(@"❌ Base64 解码失败，请粘贴完整导出字符串"); });
            return;
        }
        
        mfKLog(@"Base64 decoded, jsonData length: %lu", (unsigned long)jsonData.length);
        NSString *rawJson = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
        mfKLog(@"Raw JSON (first 200): %@", rawJson ? [rawJson substringToIndex:MIN(200, rawJson.length)] : @"(non-utf8)");
        
        NSError *jsonErr = nil;
        NSArray *importArray = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&jsonErr];
        
        // 如果不是有效 JSON 数组，尝试当作单个 base64 data 字符串处理
        NSMutableArray *itemsToRestore = [NSMutableArray array];
        BOOL isSingleItem = NO;
        
        if (jsonErr || !importArray) {
            mfKLog(@"Not a JSON array, trying single base64 item");
            // 当作单个 base64 data 字符串
            NSString *singleBase64 = rawJson ?: @"";
            NSData *itemData = [[NSData alloc] initWithBase64EncodedString:singleBase64 options:0];
            if (itemData) {
                isSingleItem = YES;
                // 需要用户提供 account/service，这里先用默认值
                NSMutableDictionary *item = [NSMutableDictionary dictionary];
                item[@"data"] = singleBase64;
                item[(__bridge id)kSecAttrAccount] = @"restored_item";
                item[(__bridge id)kSecAttrService] = @"MinisFix_Restore";
                item[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
                [itemsToRestore addObject:item];
                mfKLog(@"Parsed single item, data length=%lu", (unsigned long)itemData.length);
            } else {
                mfKLog(@"JSON parse failed and not valid base64: %@", jsonErr);
                dispatch_async(dispatch_get_main_queue(), ^{ mfToast(@"❌ 无法解析输入：不是导出 JSON 也不是 Base64"); });
                return;
            }
        } else {
            mfKLog(@"Parsed %lu items from JSON", (unsigned long)importArray.count);
            [itemsToRestore addObjectsFromArray:importArray];
        }
        
        NSUInteger successCount = 0, failCount = 0, duplicateCount = 0;
        NSMutableArray *details = [NSMutableArray array];
        
        for (NSDictionary *item in itemsToRestore) {
            NSData *data = nil;
            if (item[@"data"]) {
                data = [[NSData alloc] initWithBase64EncodedString:item[@"data"] options:0];
            }
            NSMutableDictionary *addQuery = [NSMutableDictionary dictionary];
            addQuery[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
            if (data) addQuery[(__bridge id)kSecValueData] = data;
            for (id key in item) {
                if (![key isEqualToString:@"data"]) addQuery[key] = item[key];
            }
            
            // 单个 item 模式且无 account/service 时：拒绝（提示走面板内说明，不再弹输入窗）
            if (isSingleItem && (!item[(__bridge id)kSecAttrAccount] || !item[(__bridge id)kSecAttrService])) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    mfToast(@"❌ 单条 Base64 需要含 service/account（请粘贴导出 JSON 数组格式）");
                });
                return;
            }
            
            OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
            NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(未知)";
            NSString *service = item[(__bridge id)kSecAttrService] ?: @"(未知)";
            
            if (status == errSecSuccess) {
                successCount++;
                [details addObject:[NSString stringWithFormat:@"✅ %@ / %@", account, service]];
            } else if (status == errSecDuplicateItem) {
                // 尝试更新
                NSDictionary *updQuery = @{
                    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                    (__bridge id)kSecAttrAccount: account,
                    (__bridge id)kSecAttrService: service
                };
                NSDictionary *updAttrs = @{ (__bridge id)kSecValueData: data ?: [NSData data] };
                OSStatus updStatus = SecItemUpdate((__bridge CFDictionaryRef)updQuery, (__bridge CFDictionaryRef)updAttrs);
                if (updStatus == errSecSuccess) {
                    duplicateCount++;
                    [details addObject:[NSString stringWithFormat:@"♻️ 已更新 %@ / %@", account, service]];
                } else {
                    failCount++;
                    [details addObject:[NSString stringWithFormat:@"❌ 更新失败 %@ / %@ (err=%d)", account, service, (int)updStatus]];
                }
            } else {
                failCount++;
                [details addObject:[NSString stringWithFormat:@"❌ 添加失败 %@ / %@ (err=%d)", account, service, (int)status]];
            }
        }
        
        mfKLog(@"Restore done: success=%lu, duplicate=%lu, fail=%lu", (unsigned long)successCount, (unsigned long)duplicateCount, (unsigned long)failCount);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            mfToast([NSString stringWithFormat:@"✅ 恢复完成: 成功 %lu · 更新 %lu · 失败 %lu",
                     (unsigned long)successCount, (unsigned long)duplicateCount, (unsigned long)failCount]);
        });
    });
    mfKLog(@"mfRestoreKeychainInBackground END (async)");
}

// 处理单个恢复项目（用户输入 account/service 后调用）
void mfProcessSingleRestoreItem(NSDictionary *item) {
    mfKLog(@"mfProcessSingleRestoreItem called");
    
    NSData *data = nil;
    if (item[@"data"]) {
        data = [[NSData alloc] initWithBase64EncodedString:item[@"data"] options:0];
    }
    NSMutableDictionary *addQuery = [NSMutableDictionary dictionary];
    addQuery[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    if (data) addQuery[(__bridge id)kSecValueData] = data;
    for (id key in item) {
        if (![key isEqualToString:@"data"]) addQuery[key] = item[key];
    }
    
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(未知)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(未知)";
    NSString *resultMsg;
    
    if (status == errSecSuccess) {
        resultMsg = [NSString stringWithFormat:@"✅ %@ / %@", account, service];
    } else if (status == errSecDuplicateItem) {
        NSDictionary *updQuery = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrAccount: account,
            (__bridge id)kSecAttrService: service
        };
        NSDictionary *updAttrs = @{ (__bridge id)kSecValueData: data ?: [NSData data] };
        OSStatus updStatus = SecItemUpdate((__bridge CFDictionaryRef)updQuery, (__bridge CFDictionaryRef)updAttrs);
        if (updStatus == errSecSuccess) {
            resultMsg = [NSString stringWithFormat:@"♻️ 已更新 %@ / %@", account, service];
        } else {
            resultMsg = [NSString stringWithFormat:@"❌ 更新失败 %@ / %@ (err=%d)", account, service, (int)updStatus];
        }
    } else {
        resultMsg = [NSString stringWithFormat:@"❌ 添加失败 %@ / %@ (err=%d)", account, service, (int)status];
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{ mfToast(resultMsg); });
}

// ====== iCloud ID 查询 (通过当前前台 App 的 Entitlements 自动获取 Container Identifier) ======

// 获取当前前台 App 的 Container Identifiers
// 关键：tweak 注入到每个 App 进程，直接用 SecTask 读自己的 Entitlements (内核级)
// outHasKVS: 返回是否声明了 ubiquity-kvstore (iCloud 键值存储)
static NSArray *mfGetFrontmostAppContainerIdentifiers(NSString **outBundleID, NSString **outAppName, BOOL *outHasKVS) {
    mfKLog(@"mfGetFrontmostAppContainerIdentifiers called (SecTask method)");
    
    // 我们就在目标 App 进程里
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    mfKLog(@"Current app bundleID: %@", bundleID);
    
    if (!bundleID || [bundleID hasPrefix:@"com.apple."]) {
        mfKLog(@"Invalid or system bundleID");
        return nil;
    }
    
    if (outBundleID) *outBundleID = bundleID;
    
    // 用 SecTask 直接从内核读当前进程的 Entitlements
    @try {
        SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
        if (!task) {
            mfKLog(@"SecTaskCreateFromSelf failed");
            return nil;
        }
        
        // 检测 ubiquity-kvstore (iCloud 键值存储)
        if (outHasKVS) {
            CFTypeRef kvsRef = SecTaskCopyValueForEntitlement(
                task,
                (__bridge CFStringRef)@"com.apple.developer.ubiquity-kvstore-identifier",
                NULL
            );
            *outHasKVS = (kvsRef != NULL);
            mfKLog(@"Has KVS entitlement: %@", kvsRef ? @"YES" : @"NO");
            if (kvsRef) CFRelease(kvsRef);
        }
        
        CFTypeRef containersRef = SecTaskCopyValueForEntitlement(
            task,
            (__bridge CFStringRef)@"com.apple.developer.icloud-container-identifiers",
            NULL
        );
        CFRelease(task);
        
        if (!containersRef) {
            mfKLog(@"No icloud-container-identifiers entitlement found");
            return nil;
        }
        
        NSArray *containerIDs = (__bridge_transfer NSArray *)containersRef;
        mfKLog(@"App %@ containers: %@", bundleID, containerIDs);
        
        // 尝试拿 App 名称
        NSDictionary *infoDict = [[NSBundle mainBundle] infoDictionary];
        NSString *appName = infoDict[@"CFBundleDisplayName"] ?: infoDict[@"CFBundleName"] ?: bundleID;
        if (outAppName) *outAppName = appName;
        
        return containerIDs;
    } @catch (NSException *e) {
        mfKLog(@"Exception: %@", e);
        return nil;
    }
}

// ====== v2.6.85 CK 启动预热（本质修法）======
// v2.6.86 补全：砸壳实锤 Picsew 链接了 CloudKit，且预热(启动后154ms)仍崩同一 once →
// 时机无关。真凶 = CK once 块的 entitlement 强校验：
//   icloud-services 必须含 "CloudKit" service 才允许用 CKContainer API。
//   Picsew 只有 ["CloudDocuments"](iCloud Drive) → 校验失败 → os_crash_internal 主动 trap。
//   Scripting 等 app 能查 = 它们的 services 含 CloudKit，once 已被 app 自己合法跑过。
// 破法：hook SecTaskCopyValueForEntitlement（用户态导出函数），key=icloud-services 时
//   在返回数组注入 "CloudKit" → CK once 校验通过 → trap 消失。其余 key 全透传。
static volatile BOOL g_ckWarmDone = NO;     // once 预热完成
static NSString *g_ckWarmContainerID = nil; // SecTask 读到的真容器 ID
static volatile BOOL g_ckHookInstalled = NO;
static volatile BOOL g_ckEntQueried = NO;   // my wrapper 是否被 CK 调用过

// v2.6.93: ck 日志落盘——trap 崩溃进程时 hostlog 内存缓冲全丢，落盘才能拿到死前现场
static void ckLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void ckLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    mfLog(@"%@", s);
    // v2.6.95: app 沙盒写不了 /var/mobile/Documents（全静默失败实证）→ 写 app 自己 Documents（重开同 app 可读，崩溃后仍在）
    static NSString *path = nil;
    if (!path) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        path = [docs stringByAppendingPathComponent:@"minisfix_ck.log"];
    }
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.dateFormat = @"MM-dd HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [df stringFromDate:[NSDate date]], s];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) { [line writeToFile:path atomically:YES]; return; }
    [fh seekToEndOfFile];
    [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

static CFTypeRef (*ckOrigSecTaskCopyValueForEntitlement)(SecTaskRef, CFStringRef, CFErrorRef *);
static CFTypeRef ckMySecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef ent, CFErrorRef *err) {
    g_ckEntQueried = YES;
    if (!ckOrigSecTaskCopyValueForEntitlement) {  // v2.6.94 防护: 定向补丁未命中时 dlsym 兜底(dlsym 不走 GOT,总是原实现)
        ckOrigSecTaskCopyValueForEntitlement = (void *)dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
        if (!ckOrigSecTaskCopyValueForEntitlement) return NULL;
    }
    CFTypeRef r = ckOrigSecTaskCopyValueForEntitlement(task, ent, err);
    if (ent && CFStringCompare(ent, CFSTR("com.apple.developer.icloud-services"), 0) == 0) {
        NSArray *arr = CFBridgingRelease(r); r = NULL;
        ckLog(@"singularAPI reads services → %@", arr ?: @"(nil)");
        // 通用规则（数据驱动，无 app 特化）：
        //   - services 数组存在但缺 "CloudKit" → 补全（任何 CloudDocuments-only app 命中同一规则）
        //   - 已含 CloudKit → 原样
        //   - 完全未声明(nil) → 原样透传，绝不给无 iCloud 的 app 伪造声明
        if ([arr isKindOfClass:[NSArray class]] && arr.count > 0 && ![arr containsObject:@"CloudKit"]) {
            NSMutableArray *m = [arr mutableCopy];
            [m addObject:@"CloudKit"];
            return CFBridgingRetain(m);
        }
        return CFBridgingRetain(arr);
    }
    return r;
}

// WithError 变体（CK 内部可能走这个）：复用同一补丁逻辑
static CFTypeRef (*ckOrigSecTaskCopyValueForEntitlementWithError)(SecTaskRef, CFStringRef, CFErrorRef *);
static CFTypeRef ckMySecTaskCopyValueForEntitlementWithError(SecTaskRef task, CFStringRef ent, CFErrorRef *err) {
    if (!ckOrigSecTaskCopyValueForEntitlementWithError) {
        ckOrigSecTaskCopyValueForEntitlementWithError = (void *)dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlementWithError");
        if (!ckOrigSecTaskCopyValueForEntitlementWithError) return NULL;
    }
    return ckMySecTaskCopyValueForEntitlement(task, ent, err);
}

// v2.6.92: 复数版 = [ckdiag] 实锤的 CK 唯一 entitlement import！签名:
//   CFDictionaryRef SecTaskCopyValuesForEntitlements(SecTaskRef, CFArrayRef keys, CFErrorRef*)
static CFDictionaryRef (*ckOrigSecTaskCopyValuesForEntitlements)(SecTaskRef, CFArrayRef, CFErrorRef *);
static CFDictionaryRef ckMySecTaskCopyValuesForEntitlements(SecTaskRef task, CFArrayRef keys, CFErrorRef *err) {
    g_ckEntQueried = YES;
    if (!ckOrigSecTaskCopyValuesForEntitlements) {  // v2.6.94 防护(selftest 崩因)
        ckOrigSecTaskCopyValuesForEntitlements = (void *)dlsym(RTLD_DEFAULT, "SecTaskCopyValuesForEntitlements");
        if (!ckOrigSecTaskCopyValuesForEntitlements) return NULL;
    }
    CFDictionaryRef d = ckOrigSecTaskCopyValuesForEntitlements(task, keys, err);
    if (d && keys) {
        for (CFIndex i = 0; i < CFArrayGetCount(keys); i++) {
            CFStringRef k = (CFStringRef)CFArrayGetValueAtIndex(keys, i);
            if (!k) continue;
            NSString *ks = (__bridge NSString *)k;
            ckLog(@"pluralAPI reads key: %@", ks);
            if ([ks isEqualToString:@"com.apple.developer.icloud-services"]) {
                NSArray *services = [(__bridge NSDictionary *)d objectForKey:ks];
                if ([services isKindOfClass:[NSArray class]] && ![services containsObject:@"CloudKit"]) {
                    NSMutableDictionary *m = [(__bridge NSDictionary *)d mutableCopy];
                    NSMutableArray *s = [services mutableCopy];
                    [s addObject:@"CloudKit"];
                    [m setObject:s forKey:ks];
                    ckLog(@"services COMPLETED via plural API: %@ → %@", services, s);
                    return CFBridgingRetain(m);
                }
            }
        }
    }
    return d;
}

// v2.6.87 第三层兜底：GOT 指针扫描补丁（不依赖 MSHook/Dobby，任何注入器环境必成）
// 原理：dyld 启动后 GOT 槽里是已解析的绝对地址 → 扫 CloudKit 镜像 __DATA* 段，
//   找到指向 SecTaskCopyValueForEntitlement 的槽 → mprotect 改写为 my 函数。
static BOOL ckPatchGOTInImage(const struct mach_header *mh, intptr_t slide, void *myFn, void *targetFn) {
    if (!mh || mh->magic != 0xfeedfacf) return NO;
    uintptr_t cur = (uintptr_t)mh + sizeof(struct mach_header_64);
    const struct load_command *lc = (const struct load_command *)cur;
    for (uint32_t i = 0; i < mh->ncmds; i++, cur += lc->cmdsize, lc = (const struct load_command *)cur) {
        if (lc->cmd != 0x19 /*LC_SEGMENT_64*/) continue;
        const struct segment_command_64 *seg = (const struct segment_command_64 *)cur;
        if (strncmp(seg->segname, "__DATA", 6) != 0) continue;  // __DATA/__DATA_CONST/__AUTH_CONST 全命中
        uintptr_t *slots = (uintptr_t *)(slide + seg->vmaddr);
        uintptr_t n = seg->vmsize / 8;
        for (uintptr_t k = 0; k < n; k++) {
            uintptr_t v = slots[k];
            // 全值匹配 或 低 47 位匹配（arm64e auth 指针兼容）
            if (v == (uintptr_t)targetFn ||
                (v & 0x7FFFFFFFFFFFULL) == ((uintptr_t)targetFn & 0x7FFFFFFFFFFFULL)) {
                uintptr_t pageStart = (uintptr_t)&slots[k] & ~0xFFFULL;
                long pz = getpagesize();
                pageStart = (uintptr_t)&slots[k] & ~(uintptr_t)(pz - 1);
                if (mprotect((void *)pageStart, pz * 2, PROT_READ | PROT_WRITE) != 0) continue;
                slots[k] = (uintptr_t)myFn;
                mprotect((void *)pageStart, pz * 2, PROT_READ);
                return YES;
            }
        }
    }
    return NO;
}

static BOOL ckPatchGOTViaScan(void) {
    void *target = dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
    if (!target) return NO;
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "CloudKit.framework/CloudKit")) continue;
        BOOL ok = ckPatchGOTInImage(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i),
                                    (void *)ckMySecTaskCopyValueForEntitlement, target);
        mfLog(@"[ckwarm] GOT scan in %s → %s", name, ok ? "PATCHED" : "no slot found");
        return ok;
    }
    mfLog(@"[ckwarm] CloudKit image not loaded yet for GOT scan");
    return NO;
}

// v2.6.90: ckPatchOutTrap 已移除——iOS 17 系统框架代码页受 PPL 保护，mprotect 表面成功但写入即 SIGSEGV（v2.6.89 全 app 崩实证）。
// 代码页不可写，但 CK 的 GOT（__DATA_CONST 数据页）可写（fishhook 已实证）。
// v2.6.91 修复地址公式：shared cache 里 __TEXT.vmaddr ≠ 0，必须用 slide + vmaddr（v2.6.90 用 ckStart+vmaddr 读飞 → 全崩实证）
// 同时把盲扫整个 __DATA 段改为只扫 __got/__auth_got 等 bind 槽 section（精确、快）
// v2.6.94: 扫描即补丁——ckdiag 已实证能精确定位复数版槽（fishhook 对该槽失效，orig=NULL → v2.6.93 selftest 调 NULL 崩）。
// 扫 __got/__auth_got，dladdr 反查符号名，目标符号直接 mprotect 改槽。数据页可写（单数版 fishhook rebind 成功实证）。
static BOOL ckHookEntitlementImports(void) {
    uint32_t cnt = _dyld_image_count();
    uintptr_t secStart = 0;
    intptr_t ckSlide = 0;
    const struct mach_header *ckh = NULL;
    for (uint32_t i = 0; i < cnt; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (!secStart && strstr(nm, "/Security")) secStart = (uintptr_t)_dyld_get_image_header(i);
        else if (!ckh && strstr(nm, "CloudKit.framework/CloudKit")) {
            ckh = _dyld_get_image_header(i);
            ckSlide = _dyld_get_image_vmaddr_slide(i);
        }
    }
    if (!ckh || !secStart) { ckLog(@"[ckpatch] not both found"); return NO; }
    BOOL patched = NO;
    long pz = getpagesize();
    uintptr_t cur = (uintptr_t)ckh + sizeof(struct mach_header_64);
    const struct load_command *lc = (const struct load_command *)cur;
    for (uint32_t i = 0; i < ckh->ncmds; i++, cur += lc->cmdsize, lc = (const struct load_command *)cur) {
        if (lc->cmd != 0x19) continue;
        const struct segment_command_64 *seg = (const struct segment_command_64 *)cur;
        const struct section_64 *sects = (const struct section_64 *)(cur + sizeof(struct segment_command_64));
        for (uint32_t s = 0; s < seg->nsects; s++) {
            const struct section_64 *sec = &sects[s];
            if (strcmp(sec->sectname, "__got") && strcmp(sec->sectname, "__auth_got") &&
                strcmp(sec->sectname, "__nl_symbol_ptr") && strcmp(sec->sectname, "__la_symbol_ptr")) continue;
            volatile uintptr_t *slots = (volatile uintptr_t *)(ckSlide + sec->addr);
            uintptr_t n = sec->size / 8;
            if (n > 100000) continue;
            for (uintptr_t k = 0; k < n; k++) {
                uintptr_t v = slots[k];
                if (v < secStart || v >= secStart + 0x400000) continue;
                Dl_info info;
                if (!dladdr((void *)v, &info) || !info.dli_sname) continue;
                void **origSlot = NULL;
                void *myfn = NULL;
                if (!strcmp(info.dli_sname, "SecTaskCopyValuesForEntitlements") && !ckOrigSecTaskCopyValuesForEntitlements) {
                    origSlot = (void **)&ckOrigSecTaskCopyValuesForEntitlements;
                    myfn = (void *)ckMySecTaskCopyValuesForEntitlements;
                } else if (!strcmp(info.dli_sname, "SecTaskCopyValueForEntitlement") && !ckOrigSecTaskCopyValueForEntitlement) {
                    origSlot = (void **)&ckOrigSecTaskCopyValueForEntitlement;
                    myfn = (void *)ckMySecTaskCopyValueForEntitlement;
                } else if (!strcmp(info.dli_sname, "SecTaskCopyValueForEntitlementWithError") && !ckOrigSecTaskCopyValueForEntitlementWithError) {
                    origSlot = (void **)&ckOrigSecTaskCopyValueForEntitlementWithError;
                    myfn = (void *)ckMySecTaskCopyValueForEntitlementWithError;
                }
                if (!origSlot) continue;
                uintptr_t page = ((uintptr_t)&slots[k]) & ~(uintptr_t)(pz - 1);
                if (mprotect((void *)page, pz * 2, PROT_READ | PROT_WRITE) != 0) {
                    ckLog(@"[ckpatch] mprotect fail for %s errno=%d", info.dli_sname, errno);
                    continue;
                }
                *origSlot = (void *)slots[k];
                slots[k] = (uintptr_t)myfn;
                mprotect((void *)page, pz * 2, PROT_READ);
                ckLog(@"[ckpatch] PATCHED %s (orig=%p)", info.dli_sname, (void *)v);
                patched = YES;
            }
        }
    }
    ckLog(@"[ckpatch] done, patched=%d (singular=%p plural=%p)", patched,
          (void *)ckOrigSecTaskCopyValueForEntitlement, (void *)ckOrigSecTaskCopyValuesForEntitlements);
    return patched;
}

// 三层 hook 引擎：MSHookFunction → fishhook(官方,支持 chained fixups) → GOT 指针扫描
static BOOL ckInstallServicesPatch(void) {
    if (ckOrigSecTaskCopyValueForEntitlement) return YES;  // 已装
    void *target = dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
    if (!target) { mfLog(@"[ckwarm] SecTaskCopyValueForEntitlement not found"); return NO; }
    // 1) MSHookFunction (Substrate/ElleKit)
    void *ms = dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (ms) {
        void *plural = dlsym(RTLD_DEFAULT, "SecTaskCopyValuesForEntitlements");
        ((void(*)(void*,void*,void**))ms)(target, (void*)ckMySecTaskCopyValueForEntitlement,
                                          (void**)&ckOrigSecTaskCopyValueForEntitlement);
        if (plural) ((void(*)(void*,void*,void**))ms)(plural, (void*)ckMySecTaskCopyValuesForEntitlements,
                                                      (void**)&ckOrigSecTaskCopyValuesForEntitlements);
        if (ckOrigSecTaskCopyValueForEntitlement || ckOrigSecTaskCopyValuesForEntitlements) {
            void *targetWE = dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlementWithError");
            if (targetWE) ((void(*)(void*,void*,void**))ms)(targetWE, (void*)ckMySecTaskCopyValueForEntitlementWithError,
                                                            (void**)&ckOrigSecTaskCopyValueForEntitlementWithError);
            mfLog(@"[ckwarm] engine=MSHookFunction installed (plural=%p)", (void*)ckOrigSecTaskCopyValuesForEntitlements);
            return YES;
        }
    }
    // 2) fishhook —— 官方实现，正确解析 iOS 15+ chained fixups / auth_got，按符号名 rebind
    {
        struct rebinding rbs[3] = {
            { "SecTaskCopyValueForEntitlement",
              (void *)ckMySecTaskCopyValueForEntitlement,
              (void **)&ckOrigSecTaskCopyValueForEntitlement },
            { "SecTaskCopyValueForEntitlementWithError",
              (void *)ckMySecTaskCopyValueForEntitlementWithError,
              (void **)&ckOrigSecTaskCopyValueForEntitlementWithError },
            { "SecTaskCopyValuesForEntitlements",           // v2.6.92: ckdiag 实锤的校验路径
              (void *)ckMySecTaskCopyValuesForEntitlements,
              (void **)&ckOrigSecTaskCopyValuesForEntitlements },
        };
        int n = rebind_symbols(rbs, 3);
        mfLog(@"[ckwarm] engine=fishhook rebind=%d singular=%p plural=%p",
              n, (void*)ckOrigSecTaskCopyValueForEntitlement, (void*)ckOrigSecTaskCopyValuesForEntitlements);
        if (ckOrigSecTaskCopyValueForEntitlement || ckOrigSecTaskCopyValuesForEntitlements) {
            mfLog(@"[ckwarm] engine=fishhook installed");
            g_ckHookInstalled = YES;
            return YES;
        }
    }
    // 3) GOT 指针扫描（无引擎依赖）
    if (ckPatchGOTViaScan()) {
        ckOrigSecTaskCopyValueForEntitlement = (void *)target;  // 记录原址供透传（扫描模式下 orig=真函数）
        mfLog(@"[ckwarm] engine=GOT-scan installed");
        return YES;
    }
    mfLog(@"[ckwarm] all engines failed (ms=%p)", ms);
    return NO;
}

// v2.6.93 自测：直接手动调 my 复数版（走 orig→补全），验证补全链路——不触发 CK once，安全
static void ckSelfTestPluralAPI(void) {
    @try {
        SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
        if (!task) { ckLog(@"selftest: SecTaskCreateFromSelf failed"); return; }
        CFArrayRef keys = (__bridge_retained CFArrayRef)(@[(@"com.apple.developer.icloud-services")]);
        CFErrorRef err = NULL;
        CFDictionaryRef d = ckMySecTaskCopyValuesForEntitlements(task, keys, &err);
        NSArray *services = d ? [(__bridge NSDictionary *)d objectForKey:@"com.apple.developer.icloud-services"] : nil;
        ckLog(@"selftest: returned services = %@", services ?: @"(nil)");
        if (d) CFRelease(d);
        CFRelease((CFArrayRef)keys);
        CFRelease(task);
    } @catch (NSException *e) {
        ckLog(@"selftest exception: %@", e);
    }
}

static NSArray *mfReadICloudContainerEntitlement(void) {
    @try {
        SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
        if (!task) return nil;
        CFTypeRef ref = SecTaskCopyValueForEntitlement(task,
            (__bridge CFStringRef)@"com.apple.developer.icloud-container-identifiers", NULL);
        CFRelease(task);
        if (!ref) return nil;
        NSArray *arr = (__bridge_transfer NSArray *)ref;
        return ([arr isKindOfClass:[NSArray class]] && arr.count > 0) ? arr : nil;
    } @catch (NSException *e) { return nil; }
}

void mfCloudKitWarmupStart(void) {
    NSArray *containers = mfReadICloudContainerEntitlement();
    if (!containers) {
        ckLog(@"no icloud entitlement in this app — skip");
        g_ckWarmDone = YES;
        return;
    }
    g_ckWarmContainerID = [containers[0] copy];
    // v2.6.93: 恢复 appUsesCK 安全门（v2.6.92 解除后 Picsew 仍 trap → 复数版补全未被校验采用）
    BOOL appUsesCK = NO;
    @try {
        SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
        if (task) {
            CFTypeRef ref = SecTaskCopyValueForEntitlement(task,
                (__bridge CFStringRef)@"com.apple.developer.icloud-services", NULL);
            NSArray *svcs = (__bridge_transfer NSArray *)ref;
            appUsesCK = [svcs isKindOfClass:[NSArray class]] && [svcs containsObject:@"CloudKit"];
            CFRelease(task);
        }
    } @catch (NSException *e) { ckLog(@"services probe exception: %@", e); }
    ckLog(@"=== warmup start cid=%@ appUsesCK=%d ===", g_ckWarmContainerID, appUsesCK);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        void *h = dlopen("/System/Library/Frameworks/CloudKit.framework/CloudKit", RTLD_LAZY);
        ckLog(@"dlopen = %p", h);
        // v2.6.94: 定向补丁为主（fishhook 对复数版槽失效实证）——扫描即补丁
        if (!ckHookEntitlementImports()) {
            ckLog(@"direct patch failed — stays guarded");
            return;
        }
        g_ckHookInstalled = YES;
        if (!appUsesCK) {
            // 不触发 once（trap 风险）。自测补全链路 + 落盘，日志可查
            ckSelfTestPluralAPI();
            ckLog(@"guarded mode: once NOT fired. Use ⚠️ force-trigger for the deadly experiment (log survives crash).");
            return;
        }
        ckLog(@"firing once (appUsesCK=YES, safe)");
        Class ck = NSClassFromString(@"CKContainer");
        if (ck) ((id(*)(id,SEL))objc_msgSend)((id)ck, NSSelectorFromString(@"defaultContainer"));
        g_ckWarmDone = YES;
        ckLog(@"done (survived) cid=%@", g_ckWarmContainerID);
    });
}

BOOL mfCloudKitWarmReady(void) { return g_ckWarmDone; }

// 核心查询函数：查单个容器的 Record ID 并回调
// v2.6.85：前提 = ctor 已预热 once。未预热完成时拒绝调用（防 trap）。
// 真 ID 优先（SecTask entitlement），无则 defaultContainer。
static void mfQueryRecordIDForContainer(NSString *containerIdentifier,
                                         void (^completion)(NSString *recordName, NSError *error)) {
    if (!g_ckWarmDone) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(nil, [NSError errorWithDomain:@"MFCloudKit" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"⏳ CloudKit 预热中，请重开本页重试"}]);
        });
        return;
    }
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // once 已在启动时跑过 → 这里调用安全（Scripting app 实测锚点：once 完成后 tweak 调 CK 无 trap）
        // 无 entitlement 的 app（g_ckWarmContainerID=nil）：once 从未预热 → 碰 CK 必 trap，硬降级
        if (!g_ckWarmContainerID) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(nil, [NSError errorWithDomain:@"MFCloudKit" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"🚫 该 App 未声明 iCloud 容器 entitlement"}]);
            });
            return;
        }
        CKContainer *container = [CKContainer containerWithIdentifier:g_ckWarmContainerID];
        if (!container) container = [CKContainer defaultContainer];
        [container fetchUserRecordIDWithCompletionHandler:^(CKRecordID *recordID, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!error && recordID) {
                    completion(recordID.recordName, nil);
                } else {
                    completion(nil, error);
                }
            });
        }];
    });
}

// iCloud ID 列表页（类似 Keychain 查看列表）
static void mfShowICloudIDListPage(NSString *bundleID, NSString *appName, NSArray *containers, BOOL hasKVS) {
    mfKLog(@"mfShowICloudIDListPage called, %lu containers, kvs=%@", (unsigned long)containers.count, hasKVS ? @"YES" : @"NO");
    
    UIView *page = mfMakePage(@"iCloud ID 列表", YES);
    
    // 加载指示
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    spinner.center = CGPointMake(g_mfCardW / 2, g_mfCardH / 2);
    spinner.hidesWhenStopped = YES;
    [page addSubview:spinner];
    [spinner startAnimating];
    
    UILabel *loadingLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, spinner.center.y + 30, g_mfCardW - 40, 20)];
    loadingLabel.text = @"查询 iCloud Record ID 中...";
    loadingLabel.textAlignment = NSTextAlignmentCenter;
    loadingLabel.textColor = [UIColor secondaryLabelColor];
    loadingLabel.font = [UIFont systemFontOfSize:14];
    [page addSubview:loadingLabel];
    
    mfPushPage(page);
    
    // ScrollView 预创建
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 40, g_mfCardW, g_mfCardH - 40)];
    sv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [page addSubview:sv];
    
    __block CGFloat y = 12;
    __block NSInteger pendingCount = containers.count;
    
    // App 信息卡片（静态）
    UIView *infoCard = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 60)];
    infoCard.backgroundColor = [UIColor tertiarySystemBackgroundColor];
    infoCard.layer.cornerRadius = 8;
    UILabel *infoLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, g_mfCardW - 48, 44)];
    infoLabel.text = [NSString stringWithFormat:@"📱 %@\n🆔 %@", appName ?: @"未知", bundleID ?: @""];
    infoLabel.font = [UIFont systemFontOfSize:13];
    infoLabel.textColor = [UIColor labelColor];
    infoLabel.numberOfLines = 0;
    [infoCard addSubview:infoLabel];
    [sv addSubview:infoCard];
    y += 68;
    
    // 分隔标题
    UILabel *sectionTitle = [[UILabel alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 24)];
    sectionTitle.text = [NSString stringWithFormat:@"iCloud 容器 (%lu)", (unsigned long)containers.count];
    sectionTitle.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    sectionTitle.textColor = [UIColor secondaryLabelColor];
    [sv addSubview:sectionTitle];
    y += 28;

    // KVS 状态行（如果声明了 ubiquity-kvstore）
    if (hasKVS) {
        UIView *kvsCell = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 56)];
        kvsCell.backgroundColor = [UIColor secondarySystemBackgroundColor];
        kvsCell.layer.cornerRadius = 8;
        
        UILabel *kvsTitle = [[UILabel alloc] initWithFrame:CGRectMake(12, 6, g_mfCardW - 48, 18)];
        kvsTitle.text = @"iCloud 键值存储 (KVS)";
        kvsTitle.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        kvsTitle.textColor = [UIColor labelColor];
        [kvsCell addSubview:kvsTitle];
        
        UILabel *kvsStatus = [[UILabel alloc] initWithFrame:CGRectMake(12, 26, g_mfCardW - 48, 24)];
        kvsStatus.text = @"ℹ️ 已启用 NSUbiquitousKeyValueStore 小数据同步";
        kvsStatus.font = [UIFont systemFontOfSize:12];
        kvsStatus.textColor = [UIColor systemBlueColor];
        kvsStatus.numberOfLines = 2;
        [kvsCell addSubview:kvsStatus];
        
        [sv addSubview:kvsCell];
        y += 64;
    }
    
    // 为每个容器查询 Record ID
    for (NSString *containerID in containers) {
        // 占位 cell
        UIView *cell = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 72)];
        cell.backgroundColor = [UIColor secondarySystemBackgroundColor];
        cell.layer.cornerRadius = 8;
        
        UILabel *containerLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 6, g_mfCardW - 48, 18)];
        containerLabel.text = containerID;
        containerLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        containerLabel.textColor = [UIColor labelColor];
        [cell addSubview:containerLabel];
        
        UILabel *statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 26, g_mfCardW - 48, 40)];
        statusLabel.text = @"⏳ 查询中...";
        statusLabel.font = [UIFont systemFontOfSize:12];
        statusLabel.textColor = [UIColor secondaryLabelColor];
        statusLabel.numberOfLines = 2;
        [cell addSubview:statusLabel];
        
        objc_setAssociatedObject(cell, "containerID", containerID, OBJC_ASSOCIATION_RETAIN);
        objc_setAssociatedObject(cell, "statusLabel", statusLabel, OBJC_ASSOCIATION_RETAIN);
        
        // 点击复制 Record ID
        UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:g_mfCtrl action:@selector(mfCopyICloudRecordID:)];
        [cell addGestureRecognizer:tap];
        
        // v2.6.84：删 v2.6.82 假 ID 探测 / 默认容器降级（推出来的 ID cloudd 不认 + 误伤）
        // 直接查 + 拿啥显啥 + error 直接显示给用户
        [sv addSubview:cell];
        y += 80;
        
        NSString *cid = containerID;
        mfQueryRecordIDForContainer(cid, ^(NSString *recordName, NSError *error) {
            UILabel *lbl = objc_getAssociatedObject(cell, "statusLabel");
            if (!lbl) return;
            
            if (error) {
                lbl.text = [NSString stringWithFormat:@"❌ %@", error.localizedDescription ?: @"查询失败"];
                lbl.textColor = [UIColor systemRedColor];
                mfKLog(@"Container %@ error: %@", cid, error);
            } else if (recordName) {
                lbl.text = [NSString stringWithFormat:@"🔑 %@", recordName];
                lbl.textColor = [UIColor systemGreenColor];
                objc_setAssociatedObject(cell, "recordID", recordName, OBJC_ASSOCIATION_RETAIN);
                mfKLog(@"Container %@ recordID: %@", cid, recordName);
            } else {
                lbl.text = @"⚠️ 未返回 Record ID";
                lbl.textColor = [UIColor systemOrangeColor];
            }
            
            pendingCount--;
            if (pendingCount <= 0) {
                [spinner stopAnimating];
                [spinner removeFromSuperview];
                [loadingLabel removeFromSuperview];
            }
            sv.contentSize = CGSizeMake(g_mfCardW, y + 20);
        });
    }

    sv.contentSize = CGSizeMake(g_mfCardW, y + 40);
}

// iCloud Record ID 复制 (从列表页点击 cell) - 导出函数
void mfCopyICloudRecordIDFromCell(UIViewController *vc, UIView *cell) {
    if (!cell) return;
    NSString *recordID = objc_getAssociatedObject(cell, "recordID");
    NSString *containerID = objc_getAssociatedObject(cell, "containerID");
    if (!recordID) {
        mfToast(@"⏳ Record ID 尚未查询完成");
        return;
    }
    [[UIPasteboard generalPasteboard] setString:recordID];
    mfKLog(@"Copied iCloud Record ID: %@ (container: %@)", recordID, containerID);
    mfToast(@"✅ 已复制 Record ID");
}
void mfFetchCloudKitRecordIDAuto(void) {
    mfKLog(@"mfFetchCloudKitRecordIDAuto called (v2.6.84: minimal)");
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"未知";
    NSDictionary *infoDict = [[NSBundle mainBundle] infoDictionary];
    NSString *appName = infoDict[@"CFBundleDisplayName"] ?: infoDict[@"CFBundleName"] ?: bundleID;
    // v2.6.84：直接走 defaultContainer + fetch，error 显示给用户，不预检
    NSMutableArray *arr = [NSMutableArray arrayWithObject:@"(默认容器)"];
    mfShowICloudIDListPage(bundleID, appName, arr, NO);
}

// ====== 面板页面 ======

// Keychain 条目摘要（列表 cell 用）
static NSString *mfItemSummary(NSDictionary *item) {
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    return [NSString stringWithFormat:@"%@ / %@", service, account];
}

// Keychain 列表控制器（UITableView + 系统左滑：复制/编辑/删除）—— 对齐捕获列表风格
@interface MFKeychainList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *records;
// 指向宿主 page（swipe 删除后控制 reload；nil=纯 dump 只读模式）
@property (nonatomic, weak) UITableView *table;
@end
@implementation MFKeychainList
- (UITableView *)mfMakeTableInPage:(UIView *)page {
    UITableView *tb = [[UITableView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42) style:UITableViewStylePlain];
    tb.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    tb.dataSource = self;
    tb.delegate = self;
    tb.backgroundColor = UIColor.clearColor;
    tb.separatorColor = [UIColor separatorColor];
    [page addSubview:tb];
    self.table = tb;
    return tb;
}
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return (NSInteger)self.records.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *id_ = @"mfkeyrow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:id_];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:id_];
    NSDictionary *item = self.records[ip.row];
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *ag = item[(__bridge id)kSecAttrAccessGroup] ?: @"";
    NSData *data = item[(__bridge id)kSecValueData];
    c.textLabel.text = service;
    c.textLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    c.detailTextLabel.text = [NSString stringWithFormat:@"%@ · %lu B%s%@",
                              account, (unsigned long)data.length,
                              ag.length ? " · " : "", ag];
    c.detailTextLabel.font = [UIFont systemFontOfSize:10];
    c.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    c.backgroundColor = UIColor.clearColor;
    if (data.length > 512) c.detailTextLabel.textColor = [UIColor systemOrangeColor]; // 大数据视觉提示
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    mfShowKeychainDetail(self.records[ip.row]);
}
// 左滑：复制 / 编辑 / 删除
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSDictionary *item = self.records[ip.row];
    UIContextualAction *copyA = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"复制" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            NSData *data = item[(__bridge id)kSecValueData];
            if (data) {
                [[UIPasteboard generalPasteboard] setString:[data base64EncodedStringWithOptions:0]];
                mfKLog(@"copied item data (service=%@)", item[(__bridge id)kSecAttrService]);
            }
            done(YES);
        }];
    copyA.backgroundColor = [UIColor systemBlueColor];
    UIContextualAction *editA = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"编辑" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            mfShowKeychainDetailMode(item, YES);  // 直接进编辑模式
            done(YES);
        }];
    editA.backgroundColor = [UIColor systemOrangeColor];
    UIContextualAction *delA = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleDestructive
        title:@"删除" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            BOOL ok = mfDeleteKeychainItemInternal(item);
            mfKLog(@"swipe delete: %@", ok ? @"OK" : @"FAIL");
            NSMutableArray *mut = [self.records mutableCopy];
            [mut removeObjectAtIndex:ip.row];
            self.records = mut;
            [tv deleteRowsAtIndexPaths:@[ip] withRowAnimation:UITableViewRowAnimationAutomatic];
            done(YES);
        }];
    delA.backgroundColor = [UIColor systemRedColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[delA, editA, copyA]];
}
@end

// 显示 Keychain 列表（表格版，左滑复制/编辑/删除）
static void mfShowKeychainListPage(void) {
    mfKLog(@"mfShowKeychainListPage called");
    UIView *page = mfMakePage(@"Keychain 列表", YES);
    
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    spinner.center = CGPointMake(g_mfCardW / 2, g_mfCardH / 2);
    spinner.hidesWhenStopped = YES;
    [page addSubview:spinner];
    [spinner startAnimating];
    
    UILabel *loadingLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, spinner.center.y + 30, g_mfCardW - 40, 20)];
    loadingLabel.text = @"查询 Keychain 中...";
    loadingLabel.textAlignment = NSTextAlignmentCenter;
    loadingLabel.textColor = [UIColor secondaryLabelColor];
    loadingLabel.font = [UIFont systemFontOfSize:14];
    [page addSubview:loadingLabel];
    
    mfPushPage(page);
    
    MFKeychainList *ctrl = [[MFKeychainList alloc] init];
    objc_setAssociatedObject(page, "mfkeylist", ctrl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray *items = mfGetKeychainItems();
        mfKLog(@"list page query done: %lu items", (unsigned long)items.count);
        dispatch_async(dispatch_get_main_queue(), ^{
            [spinner stopAnimating];
            [spinner removeFromSuperview];
            [loadingLabel removeFromSuperview];
            if (items.count == 0) {
                UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, 50, g_mfCardW - 40, 40)];
                label.text = @"无 Generic Password 项";
                label.textAlignment = NSTextAlignmentCenter;
                label.textColor = [UIColor secondaryLabelColor];
                label.font = [UIFont systemFontOfSize:15];
                [page addSubview:label];
                return;
            }
            ctrl.records = items;
            [ctrl mfMakeTableInPage:page];
        });
    });
}

// ====== Keychain Dump（当前 App 取证：装破解版跑一次→dump 看假记录格式） ======

// 判断条目是否属于当前 app（accessGroup 通常为 TEAMID.bundleid，service 常用 bundleid 前缀）
static BOOL mfItemBelongsToApp(NSDictionary *item, NSString *bundleId) {
    if (bundleId.length == 0) return NO;
    NSString *ag = item[(__bridge id)kSecAttrAccessGroup] ?: @"";
    NSString *sv = item[(__bridge id)kSecAttrService] ?: @"";
    if ([ag rangeOfString:bundleId].location != NSNotFound) return YES;
    if ([sv rangeOfString:bundleId].location != NSNotFound) return YES;
    if ([ag hasSuffix:bundleId]) return YES;
    return NO;
}

// 条目 → JSON 可序列化（完整属性）
static NSDictionary *mfItemToDumpDict(NSDictionary *item) {
    NSData *data = item[(__bridge id)kSecValueData];
    return @{
        @"service": item[(__bridge id)kSecAttrService] ?: @"",
        @"account": item[(__bridge id)kSecAttrAccount] ?: @"",
        @"accessGroup": item[(__bridge id)kSecAttrAccessGroup] ?: @"",
        @"type": item[(__bridge id)kSecAttrType] ?: @"",
        @"dataBase64": data ? [data base64EncodedStringWithOptions:0] : @"",
        @"dataLength": @(data.length),
    };
}

// Dump 当前 App Keychain（消息提示 + 落盘 + 面板列表）
void mfDumpCurrentAppKeychain(void) {
    mfKLog(@"mfDumpCurrentAppKeychain called");
    NSString *bundleId = mfCurrentBundleId();
    if (bundleId.length == 0) {
        mfToast(@"⚠️ 无法确定当前前台 App");
        return;
    }
    mfKLog(@"dumping keychain for app: %@", bundleId);
    
    UIView *page = mfMakePage([NSString stringWithFormat:@"Dump %@", bundleId], YES);
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    spinner.center = CGPointMake(g_mfCardW / 2, g_mfCardH / 2);
    spinner.hidesWhenStopped = YES;
    [page addSubview:spinner];
    [spinner startAnimating];
    UILabel *loadingLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, spinner.center.y + 30, g_mfCardW - 40, 20)];
    loadingLabel.text = @"查询 Keychain 中...";
    loadingLabel.textAlignment = NSTextAlignmentCenter;
    loadingLabel.textColor = [UIColor secondaryLabelColor];
    loadingLabel.font = [UIFont systemFontOfSize:14];
    [page addSubview:loadingLabel];
    mfPushPage(page);
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray *items = mfGetKeychainItems();
        NSMutableArray *matched = [NSMutableArray array];
        for (NSDictionary *it in items)
            if (mfItemBelongsToApp(it, bundleId)) [matched addObject:it];
        mfKLog(@"dump: total=%lu matched=%lu", (unsigned long)items.count, (unsigned long)matched.count);
        
        // 落盘 JSON（完整 dump，含全部条目 + 匹配标记）
        NSMutableArray *all = [NSMutableArray array];
        for (NSDictionary *it in items) {
            NSMutableDictionary *d = [mfItemToDumpDict(it) mutableCopy];
            d[@"belongsToApp"] = @(mfItemBelongsToApp(it, bundleId));
            [all addObject:d];
        }
        NSDictionary *dump = @{@"app": bundleId, @"dumpedAt": [NSDate date].description ?: @"", @"total": @(items.count), @"matched": @(matched.count), @"items": all};
        NSString *path = @"/var/mobile/Documents";
        [[NSFileManager defaultManager] createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *file = [NSString stringWithFormat:@"%@/minisfix_keychain_dump_%@.json", path, bundleId];
        NSData *json = [NSJSONSerialization dataWithJSONObject:dump options:NSJSONWritingPrettyPrinted error:nil];
        BOOL wrote = json && [json writeToFile:file atomically:YES];
        mfKLog(@"dump saved: %@ wrote=%d", file, wrote);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [spinner stopAnimating];
            [spinner removeFromSuperview];
            [loadingLabel removeFromSuperview];
            
            UILabel *hdr = [[UILabel alloc] initWithFrame:CGRectMake(12, 46, g_mfCardW - 24, 34)];
            hdr.text = [NSString stringWithFormat:@"总 %lu · 匹配 %lu%s%@",
                        (unsigned long)items.count, (unsigned long)matched.count,
                        wrote ? " · ✅ 已存 " : " · ⚠️ 存文件失败 ",
                        wrote ? file : @""];
            hdr.font = [UIFont systemFontOfSize:10];
            hdr.textColor = [UIColor secondaryLabelColor];
            hdr.numberOfLines = 3;
            [page addSubview:hdr];
            
            UIButton *copyAll = [UIButton buttonWithType:UIButtonTypeSystem];
            copyAll.frame = CGRectMake(12, 84, (g_mfCardW - 36) / 2, 34);
            [copyAll setTitle:@"📋 复制全部 JSON" forState:UIControlStateNormal];
            copyAll.titleLabel.font = [UIFont systemFontOfSize:12];
            copyAll.backgroundColor = [UIColor secondarySystemBackgroundColor];
            copyAll.layer.cornerRadius = 8;
            objc_setAssociatedObject(copyAll, "dumpJson", json ? json : [NSData data], OBJC_ASSOCIATION_RETAIN);
            [copyAll addTarget:g_mfCtrl action:@selector(mfCopyDumpJson:) forControlEvents:UIControlEventTouchUpInside];
            [page addSubview:copyAll];
            
            UIButton *copyMatched = [UIButton buttonWithType:UIButtonTypeSystem];
            copyMatched.frame = CGRectMake(24 + (g_mfCardW - 36) / 2, 84, (g_mfCardW - 36) / 2, 34);
            [copyMatched setTitle:@"📋 复制匹配 JSON" forState:UIControlStateNormal];
            copyMatched.titleLabel.font = [UIFont systemFontOfSize:12];
            copyMatched.backgroundColor = [UIColor secondarySystemBackgroundColor];
            copyMatched.layer.cornerRadius = 8;
            NSMutableArray *mp = [NSMutableArray array];
            for (NSDictionary *it in matched) [mp addObject:mfItemToDumpDict(it)];
            NSData *mjson = [NSJSONSerialization dataWithJSONObject:@{@"app": bundleId, @"items": mp} options:NSJSONWritingPrettyPrinted error:nil];
            objc_setAssociatedObject(copyMatched, "dumpJson", mjson ?: [NSData data], OBJC_ASSOCIATION_RETAIN);
            [copyMatched addTarget:g_mfCtrl action:@selector(mfCopyDumpJson:) forControlEvents:UIControlEventTouchUpInside];
            [page addSubview:copyMatched];
            
            if (matched.count == 0) {
                UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, 130, g_mfCardW - 40, 40)];
                label.text = @"无匹配条目（可切「全部」查看所有）";
                label.textAlignment = NSTextAlignmentCenter;
                label.textColor = [UIColor secondaryLabelColor];
                label.font = [UIFont systemFontOfSize:13];
                [page addSubview:label];
            }
            
            // 复用列表控制器（只读+复制模式：swipe 删除也保留，可顺手清理）
            MFKeychainList *ctrl = [[MFKeychainList alloc] init];
            ctrl.records = matched.count ? matched : items;
            ctrl.table = nil;
            UITableView *tb = [[UITableView alloc] initWithFrame:CGRectMake(0, 126, g_mfCardW, g_mfCardH - 126) style:UITableViewStylePlain];
            tb.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
            tb.dataSource = ctrl;
            tb.delegate = ctrl;
            tb.backgroundColor = UIColor.clearColor;
            objc_setAssociatedObject(page, "mfkeylist", ctrl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            [page addSubview:tb];
        });
    });
}

// 复制 dump JSON（由按钮调用）
void mfCopyDumpJsonFromButton(UIButton *btn) {
    NSData *json = objc_getAssociatedObject(btn, "dumpJson");
    if (json.length) {
        [[UIPasteboard generalPasteboard] setString:[[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding]];
        mfKLog(@"copied dump JSON (%lu bytes)", (unsigned long)json.length);
    }
}

// ====== 详情页（面板式，替代弹窗） ======

static void mfDoSaveKeychainData(NSDictionary *item, NSData *newData, void (^done)(BOOL)) {
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    NSString *account = item[(__bridge id)kSecAttrAccount];
    NSString *service = item[(__bridge id)kSecAttrService];
    if (account) query[(__bridge id)kSecAttrAccount] = account;
    if (service) query[(__bridge id)kSecAttrService] = service;
    NSDictionary *attrs = @{(__bridge id)kSecValueData: newData};
    OSStatus st = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);
    mfKLog(@"SecItemUpdate(%@) status=%d", service, (int)st);
    done(st == errSecSuccess);
}

// 详情面板：信息 + Base64/Hex/UTF8 查看 + 复制/编辑/删除
void mfShowKeychainDetail(NSDictionary *item) { mfShowKeychainDetailMode(item, NO); }

static void mfShowKeychainDetailMode(NSDictionary *item, BOOL autoEdit) {
    mfKLog(@"mfShowKeychainDetailMode called (autoEdit=%d) for account=%@", autoEdit, item[(__bridge id)kSecAttrAccount] ?: @"(nil)");
    UIView *page = mfMakePage(@"Keychain 详情", YES);
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *ag = item[(__bridge id)kSecAttrAccessGroup] ?: @"(无)";
    NSDate *cd = item[(__bridge id)kSecAttrCreationDate];
    NSDate *md = item[(__bridge id)kSecAttrModificationDate];
    NSData *data = item[(__bridge id)kSecValueData];
    
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
    sv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [page addSubview:sv];
    
    CGFloat y = 12;
    // 信息卡
    UIView *infoCard = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 92)];
    infoCard.backgroundColor = [UIColor secondarySystemBackgroundColor];
    infoCard.layer.cornerRadius = 8;
    UILabel *sLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 6, g_mfCardW - 44, 16)];
    sLabel.text = [NSString stringWithFormat:@"服务: %@", service];
    sLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
    UILabel *aLbl = [[UILabel alloc] initWithFrame:CGRectMake(10, 24, g_mfCardW - 44, 16)];
    aLbl.text = [NSString stringWithFormat:@"账号: %@", account];
    aLbl.font = [UIFont systemFontOfSize:11];
    UILabel *gLbl = [[UILabel alloc] initWithFrame:CGRectMake(10, 42, g_mfCardW - 44, 16)];
    gLbl.text = [NSString stringWithFormat:@"Group: %@", ag];
    gLbl.font = [UIFont systemFontOfSize:11];
    UILabel *tLbl = [[UILabel alloc] initWithFrame:CGRectMake(10, 60, g_mfCardW - 44, 26)];
    tLbl.text = [NSString stringWithFormat:@"数据 %lu B · 创建: %@ · 修改: %@",
                 (unsigned long)data.length,
                 cd ? [cd descriptionWithLocale:nil] : @"-",
                 md ? [md descriptionWithLocale:nil] : @"-"];  // v2.6.70: 之前 %@ 数量与实参不匹配(5 vs 6)导致取到栈上垃圾(NSIndexPath)崩
    tLbl.font = [UIFont systemFontOfSize:9];
    tLbl.textColor = [UIColor secondaryLabelColor];
    tLbl.numberOfLines = 2;
    [infoCard addSubview:sLabel];
    [infoCard addSubview:aLbl];
    [infoCard addSubview:gLbl];
    [infoCard addSubview:tLbl];
    [sv addSubview:infoCard];
    y += 100;
    
    // v2.6.68 布局修正：先模式按钮、再 dataView，杜绝重叠
    NSArray *modes = @[@"Base64", @"Hex", @"UTF8"];
    CGFloat segW = (g_mfCardW - 24 - 12) / 3;
    CGFloat btnY = y;                  // 模式按钮行 y≈112
    CGFloat dvY = btnY + 38;           // dataView 起点 ≈150
    CGFloat bottomZone = 132;          // 复制/编辑/删除预留(36+44+44)
    
    UITextView *dataView = [[UITextView alloc] initWithFrame:CGRectMake(12, dvY, g_mfCardW - 24, g_mfCardH - dvY - bottomZone)];
    dataView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    dataView.layer.cornerRadius = 8;
    dataView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    dataView.editable = NO;
    dataView.dataDetectorTypes = UIDataDetectorTypeNone;
    dataView.textColor = [UIColor labelColor];
    [sv addSubview:dataView];
    
    NSData *displayData = data ?: [NSData data];
    NSString *b64 = [displayData base64EncodedStringWithOptions:0];
    dataView.text = b64.length > 4096 ? [[b64 substringToIndex:4096] stringByAppendingFormat:@"\n… (共 %lu 字符, 完整用复制)", (unsigned long)b64.length] : b64;
    
    NSMutableArray *modeBtns = [NSMutableArray array];
    for (NSUInteger mi = 0; mi < modes.count; mi++) {
        UIButton *mb = [UIButton buttonWithType:UIButtonTypeSystem];
        mb.frame = CGRectMake(12 + mi * (segW + 6), btnY, segW, 30);
        [mb setTitle:modes[mi] forState:UIControlStateNormal];
        mb.titleLabel.font = [UIFont systemFontOfSize:12];
        mb.backgroundColor = [UIColor tertiarySystemBackgroundColor];
        mb.layer.cornerRadius = 6;
        objc_setAssociatedObject(mb, "mode", @(mi), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(mb, "data", displayData, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(mb, "dataView", dataView, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [mb addTarget:g_mfCtrl action:@selector(mfKeychainDataDisplay:) forControlEvents:UIControlEventTouchUpInside];
        [sv addSubview:mb];
        [modeBtns addObject:mb];
    }
    objc_setAssociatedObject(dataView, "modeBtns", modeBtns, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    
    // v2.6.69 键盘附件工具条：💾保存并收起 / ⌨️收起（键盘弹出时底部按钮被遮，toolbar 是唯一操作入口）
    UIToolbar *kbBar = [[UIToolbar alloc] initWithFrame:CGRectMake(0, 0, g_mfCardW, 44)];
    kbBar.barStyle = UIBarStyleDefault;
    UIBarButtonItem *saveI = [[UIBarButtonItem alloc] initWithTitle:@"💾 保存并收起" style:UIBarButtonItemStylePlain target:g_mfCtrl action:@selector(mfKbSaveAndDismiss:)];
    saveI.tintColor = [UIColor systemGreenColor];
    UIBarButtonItem *dismissI = [[UIBarButtonItem alloc] initWithTitle:@"⌨️ 收起" style:UIBarButtonItemStylePlain target:g_mfCtrl action:@selector(mfKbDismissKeyboard:)];
    dismissI.tintColor = [UIColor labelColor];
    kbBar.items = @[[[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil],
                    dismissI,
                    saveI];
    dataView.inputAccessoryView = kbBar;
    objc_setAssociatedObject(saveI, "dataView", dataView, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(dismissI, "dataView", dataView, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    
    y = dvY + (g_mfCardH - dvY - bottomZone) + 8;
    
    // 底部按钮行（复制/编辑/删除 → g_mfCtrl 转发，与列表 swipe 动作一致）
    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(12, y, (g_mfCardW - 36 - 24) / 2, 36);
    [copyBtn setTitle:@"📋 复制数据" forState:UIControlStateNormal];
    copyBtn.titleLabel.font = [UIFont systemFontOfSize:13];
    copyBtn.backgroundColor = [UIColor secondarySystemBackgroundColor];
    copyBtn.layer.cornerRadius = 8;
    objc_setAssociatedObject(copyBtn, "data", displayData, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [copyBtn addTarget:g_mfCtrl action:@selector(mfCopyKeychainData:) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:copyBtn];
    
    UIButton *editBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    editBtn.frame = CGRectMake(28 + (g_mfCardW - 36 - 24) / 2, y, (g_mfCardW - 36 - 24) / 2, 36);
    [editBtn setTitle:@"✏️ 编辑数据" forState:UIControlStateNormal];
    editBtn.titleLabel.font = [UIFont systemFontOfSize:13];
    editBtn.backgroundColor = [UIColor secondarySystemBackgroundColor];
    editBtn.layer.cornerRadius = 8;
    objc_setAssociatedObject(editBtn, "item", item, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(editBtn, "dataView", dataView, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(dataView, "detailEditBtn", editBtn, OBJC_ASSOCIATION_RETAIN_NONATOMIC); // toolbar 保存回查用
    [editBtn addTarget:g_mfCtrl action:@selector(mfEditKeychainData:) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:editBtn];
    y += 44;
    
    UIButton *delBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    delBtn.frame = CGRectMake(12, y, g_mfCardW - 24, 36);
    [delBtn setTitle:@"🗑 删除条目" forState:UIControlStateNormal];
    [delBtn setTitleColor:[UIColor systemRedColor] forState:UIControlStateNormal];
    delBtn.titleLabel.font = [UIFont systemFontOfSize:13];
    delBtn.backgroundColor = [UIColor secondarySystemBackgroundColor];
    delBtn.layer.cornerRadius = 8;
    objc_setAssociatedObject(delBtn, "item", item, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [delBtn addTarget:g_mfCtrl action:@selector(mfDeleteKeychainItem:) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:delBtn];
    y += 44;
    
    sv.contentSize = CGSizeMake(g_mfCardW, y + 20);
    mfPushPage(page);
    if (autoEdit) mfKeychainEnterEdit(editBtn);  // 左滑「编辑」直接进入编辑模式
}

// 详情页 C 实现：模式切换（Base64/Hex/UTF8）
void mfKeychainDataDisplayFromButton(UIButton *btn) {
    NSInteger mode = [objc_getAssociatedObject(btn, "mode") integerValue];
    NSData *d = objc_getAssociatedObject(btn, "data");
    UITextView *dv = objc_getAssociatedObject(btn, "dataView");
    if (!dv || !d) return;
    if (mode == 0) {
        NSString *b = [d base64EncodedStringWithOptions:0];
        dv.text = b.length > 4096 ? [[b substringToIndex:4096] stringByAppendingFormat:@"\n… (共 %lu 字符, 完整用复制)", (unsigned long)b.length] : b;
    } else if (mode == 1) {
        const unsigned char *p = d.bytes;
        NSMutableString *h = [NSMutableString string];
        NSUInteger n = MIN(d.length, 2048);
        for (NSUInteger i = 0; i < n; i++) [h appendFormat:@"%02X ", p[i]];
        dv.text = d.length > 2048 ? [h stringByAppendingFormat:@"\n… (共 %lu 字节, 完整用复制)", (unsigned long)d.length] : h;
    } else {
        NSString *u = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        dv.text = u ?: @"(非 UTF8 可解析数据)";
    }
}

// 详情页 C 实现：复制数据（base64 全量）
void mfCopyKeychainDataFromDetailButton(UIButton *btn) {
    NSData *d = objc_getAssociatedObject(btn, "data");
    if (!d) return;
    [[UIPasteboard generalPasteboard] setString:[d base64EncodedStringWithOptions:0]];
    mfKLog(@"detail: copied %lu bytes", (unsigned long)d.length);
    mfToast(@"✅ 已复制数据 (Base64)");
}

// 详情页 C 实现：进入编辑模式（设置文本框可写 + 面板窗口 makeKey 让键盘弹出）
static void mfKeychainEnterEdit(UIButton *btn) {
    NSDictionary *item = objc_getAssociatedObject(btn, "item");
    UITextView *dv = objc_getAssociatedObject(btn, "dataView");
    if (!item || !dv) { mfKLog(@"edit: missing assoc (item=%p dv=%p)", item, dv); return; }
    mfKLog(@"enter edit mode: service=%@", item[(__bridge id)kSecAttrService]);
    NSString *cur = objc_getAssociatedObject(btn, "origB64");
    if (!cur) {
        NSData *od = item[(__bridge id)kSecValueData];
        cur = od ? [od base64EncodedStringWithOptions:0] : @"";
        objc_setAssociatedObject(btn, "origB64", cur, OBJC_ASSOCIATION_COPY_NONATOMIC);
    }
    dv.editable = YES;
    dv.backgroundColor = [UIColor systemBackgroundColor];
    dv.text = cur;
    // 关键：面板在独立 UIWindow(Alert+1000) 且从未 makeKey —— 不 makeKey 则 becomeFirstResponder 无效(无键盘)
    UIWindow *win = nil;
    UIView *v = dv;
    while (v && ![v isKindOfClass:[UIWindow class]]) v = v.superview;
    if ([v isKindOfClass:[UIWindow class]]) win = (UIWindow *)v;
    if (win && !win.isKeyWindow) {
        [win makeKeyWindow];  // 不走 makeKeyAndVisible(避免 hidden 翻转/层级重排)
        mfKLog(@"edit: made panel window key");
    }
    [dv becomeFirstResponder];
    [btn setTitle:@"💾 保存修改" forState:UIControlStateNormal];
    objc_setAssociatedObject(btn, "editing", @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    mfToast(@"粘贴新的 Base64 数据后点保存");
}

// 详情页 C 实现：保存编辑（base64 decode → SecItemUpdate）
static void mfKeychainSaveEdit(UIButton *btn) {
    NSDictionary *item = objc_getAssociatedObject(btn, "item");
    UITextView *dv = objc_getAssociatedObject(btn, "dataView");
    if (!item || !dv) { mfKLog(@"save: missing assoc"); return; }
    NSString *text = dv.text;
    text = [text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSData *newData = [[NSData alloc] initWithBase64EncodedString:text options:0];
    if (!newData) { mfKLog(@"save: base64 decode failed"); mfToast(@"⚠️ Base64 解码失败"); return; }
    BOOL ok = NO;
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    NSString *account = item[(__bridge id)kSecAttrAccount];
    NSString *service = item[(__bridge id)kSecAttrService];
    if (account) query[(__bridge id)kSecAttrAccount] = account;
    if (service) query[(__bridge id)kSecAttrService] = service;
    NSDictionary *attrs = @{(__bridge id)kSecValueData: newData};
    OSStatus st = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);
    ok = (st == errSecSuccess);
    mfKLog(@"save: SecItemUpdate(service=%@) status=%d", service, (int)st);
    dv.editable = NO;
    dv.backgroundColor = [UIColor secondarySystemBackgroundColor];
    [dv resignFirstResponder];
    NSString *newB64 = [newData base64EncodedStringWithOptions:0];
    dv.text = newB64;
    // 同步刷新三个模式按钮持有的 data（否则显示旧数据）
    NSArray *modeBtns = objc_getAssociatedObject(dv, "modeBtns");
    for (UIButton *mb in modeBtns) objc_setAssociatedObject(mb, "data", newData, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    // 同步详情页 item 缓存（删除/二次编辑用新值）
    NSMutableDictionary *upItem = [item mutableCopy];
    upItem[(__bridge id)kSecValueData] = newData;
    objc_setAssociatedObject(btn, "item", upItem, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(btn, "origB64", newB64, OBJC_ASSOCIATION_COPY_NONATOMIC);
    [btn setTitle:@"✏️ 编辑数据" forState:UIControlStateNormal];
    objc_setAssociatedObject(btn, "editing", @NO, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    mfToast(ok ? @"✅ 已保存" : @"❌ 保存失败");
}

// 详情页 C 实现：编辑/保存数据（第一次点=进入编辑，第二次点=保存）
void mfEditKeychainDataFromDetailButton(UIButton *btn) {
    BOOL editing = [objc_getAssociatedObject(btn, "editing") boolValue];
    if (!editing) mfKeychainEnterEdit(btn);
    else mfKeychainSaveEdit(btn);
}

// v2.6.69 键盘附件工具条：💾 保存并收起（走详情页编辑按钮的保存逻辑）
void mfKbSaveAndDismissFromBar(UIBarButtonItem *item) {
    UITextView *dv = objc_getAssociatedObject(item, "dataView");
    if (!dv) return;
    UIButton *editBtn = objc_getAssociatedObject(dv, "detailEditBtn");
    if (editBtn && [objc_getAssociatedObject(editBtn, "editing") boolValue]) {
        mfKeychainSaveEdit(editBtn);   // 保存(内部已 resignFirstResponder)
    } else {
        [dv resignFirstResponder];     // 不在编辑态则直接收起
    }
}

// v2.6.69 键盘附件工具条：⌨️ 收起
void mfKbDismissKeyboardFromBar(UIBarButtonItem *item) {
    UITextView *dv = objc_getAssociatedObject(item, "dataView");
    if (dv) {
        [dv resignFirstResponder];
        mfKLog(@"keyboard dismissed via accessory bar");
    }
}

// 删除 Keychain 项 (从列表页按钮调用) - 外部可见
void mfDeleteKeychainItem(UIButton *btn) {
    mfKLog(@"mfDeleteKeychainItem handler called");
    NSDictionary *item = objc_getAssociatedObject(btn, "item");
    if (!item) {
        mfKLog(@"ERROR: no item associated with button");
        return;
    }
    
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"删除 Keychain 项"
                                                                   message:[NSString stringWithFormat:@"确定删除？\n%@ / %@", account, service]
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"删除" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        mfKLog(@"user confirmed delete");
        BOOL ok = mfDeleteKeychainItemInternal(item);
        mfKLog(@"delete result: %@", ok ? @"YES" : @"NO");
        dispatch_async(dispatch_get_main_queue(), ^{
            if (ok) {
                mfKLog(@"refreshing keychain pages");
                mfPopPage();                       // 离开详情/列表
                mfRefreshKeychainListIfVisible();  // 刷新可见列表（若有）
                mfToast(@"✅ 已删除");
            } else {
                mfToast(@"❌ 删除失败");
            }
        });
    }]];
    mfPresentOnPanelVC(alert);
}

// 刷新当前可见的 Keychain 列表（删除后同步）
static void mfRefreshKeychainListIfVisible(void) {
    for (UIView *v in g_mfPanelRootVC.view.subviews) {
        MFKeychainList *ctrl = objc_getAssociatedObject(v, "mfkeylist");
        if (ctrl && ctrl.table) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                NSArray *items = mfGetKeychainItems();
                dispatch_async(dispatch_get_main_queue(), ^{
                    ctrl.records = items;
                    [ctrl.table reloadData];
                    mfKLog(@"keychain list refreshed: %lu items", (unsigned long)items.count);
                });
            });
            return;
        }
    }
}

// 从粘贴板恢复（面板页：多行粘贴区 + 恢复按钮 + 状态行，无弹窗）
static void mfShowRestorePrompt(void) {
    mfKLog(@"mfShowRestorePrompt called (panel version)");
    UIView *page = mfMakePage(@"从剪贴板恢复", YES);
    
    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(12, 48, g_mfCardW - 24, 32)];  // v2.6.68: 避开返回按钮行(42px)
    hint.text = @"粘贴「导出到剪贴板」生成的内容（Base64 JSON 数组）\n完成后浮层提示结果";
    hint.font = [UIFont systemFontOfSize:11];
    hint.textColor = [UIColor secondaryLabelColor];
    hint.numberOfLines = 2;
    [page addSubview:hint];
    
    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(12, 84, g_mfCardW - 24, g_mfCardH - 84 - 130)];
    tv.backgroundColor = [UIColor secondarySystemBackgroundColor];
    tv.layer.cornerRadius = 8;
    tv.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    tv.textColor = [UIColor labelColor];
    tv.autoresizingMask = UIViewAutoresizingFlexibleHeight;
    mfAttachKbBar(tv);   // v2.7.1: 键盘收起工具条
    [page addSubview:tv];
    
    UILabel *stateLb = [[UILabel alloc] initWithFrame:CGRectMake(12, g_mfCardH - 60, g_mfCardW - 24, 20)];
    stateLb.text = @"";
    stateLb.font = [UIFont systemFontOfSize:11];
    stateLb.textColor = [UIColor secondaryLabelColor];
    [page addSubview:stateLb];
    
    UIButton *restoreBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    restoreBtn.frame = CGRectMake(12, g_mfCardH - 92, g_mfCardW - 24, 36);
    [restoreBtn setTitle:@"🚀 恢复" forState:UIControlStateNormal];
    restoreBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    restoreBtn.backgroundColor = [UIColor systemGreenColor];
    [restoreBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    restoreBtn.layer.cornerRadius = 8;
    objc_setAssociatedObject(restoreBtn, "textView", tv, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(restoreBtn, "resultLabel", stateLb, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [restoreBtn addTarget:g_mfCtrl action:@selector(mfDoRestoreFromPage:) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:restoreBtn];
    
    mfPushPage(page);
}

// 恢复按钮处理（页面版）
void mfDoRestoreFromPageButton(UIButton *btn) {
    UITextView *tv = objc_getAssociatedObject(btn, "textView");
    UILabel *rl = objc_getAssociatedObject(btn, "resultLabel");
    NSString *text = tv.text ? [tv.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] : @"";
    if (text.length == 0) {
        mfToast(@"❌ 输入为空");
        if (rl) rl.text = @"❌ 输入为空";
        return;
    }
    mfKLog(@"restore from page: input length=%lu", (unsigned long)text.length);
    if (rl) { rl.text = @"⏳ 后台恢复中…（完成见浮层提示）"; rl.textColor = [UIColor systemOrangeColor]; }
    mfRestoreKeychainInBackground(text);
}

// ====== 面板入口 ======

// Keychain 主页
void mfShowKeychainManagerPage(void) {
    mfKLog(@"mfShowKeychainManagerPage called");
    
    UIView *page = mfMakePage(@"Keychain 管理", YES);
    CGFloat gw = (g_mfCardW - 32 - 12) / 2;
    CGFloat gy = 48;
    
    gy = mfGridButton(page, 16, gy, gw, @"查看列表", @"📋", @selector(mfShowKeychainListPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"Dump 当前 App", @"🔎", @selector(mfDumpCurrentApp), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"获取 iCloud ID", @"☁️", @selector(mfFetchCloudKitRecordIDAuto), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"导出到剪贴板", @"📤", @selector(mfCopyKeychainAction), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"从剪贴板恢复", @"📥", @selector(mfShowRestorePromptAction), NO, nil);
    
    mfPushPage(page);
}

// 转发方法
void mfShowKeychainListPageAction(void) { 
    mfKLog(@"mfShowKeychainListPageAction called");
    mfShowKeychainListPage(); 
}
void mfCopyKeychainAction(void) { 
    mfKLog(@"mfCopyKeychainAction called");
    mfCopyKeychainInBackground(); 
}
void mfShowRestorePromptAction(void) { 
    mfKLog(@"mfShowRestorePromptAction called");
    mfShowRestorePrompt(); 
}