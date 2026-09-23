// MFKeychainManagerController.m — Keychain 管理设置页实现
// 设置页入口：查看列表 / 导出 / 导入

#import "MFKeychainManagerController.h"
#import <UIKit/UIKit.h>
#import <Security/Security.h>

static NSArray *mfGetKeychainItems(void);
static NSString *mfFormatSummary(NSDictionary *item);
static NSString *mfFormatDetail(NSDictionary *item);

static NSArray *mfGetKeychainItems(void) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) return @[];
    if (status != errSecSuccess) return @[];
    return (__bridge_transfer NSArray *)result;
}

static NSString *mfFormatSummary(NSDictionary *item) {
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    return [NSString stringWithFormat:@"%@ / %@", account, service];
}

static NSString *mfFormatDetail(NSDictionary *item) {
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    NSData *data = item[(__bridge id)kSecValueData];
    NSString *dataStr = data ? [data base64EncodedStringWithOptions:0] : @"(无数据)";
    return [NSString stringWithFormat:@"账号: %@\n服务: %@\n数据(Base64): %@", account, service, dataStr];
}

@interface MFKeychainManagerController ()
@property (nonatomic, strong) UIAlertController *loadingAlert;
@property (nonatomic, copy) NSString *restoreResultMessage;
@property (nonatomic, assign) BOOL restoreSuccess;
@end

@implementation MFKeychainManagerController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Keychain 管理";
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self showMainMenu];
}

- (void)showMainMenu {
    UIAlertController *menu = [UIAlertController alertControllerWithTitle:@"Keychain 管理"
                                                                  message:nil
                                                           preferredStyle:UIAlertControllerStyleActionSheet];
    
    [menu addAction:[UIAlertAction actionWithTitle:@"查看 Keychain 列表" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self showKeychainList];
    }]];
    
    [menu addAction:[UIAlertAction actionWithTitle:@"导出 Keychain (Base64→剪贴板)" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self copyKeychainToPasteboard];
    }]];
    
    [menu addAction:[UIAlertAction actionWithTitle:@"导入/恢复 Keychain (从剪贴板)" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self showRestorePrompt];
    }]];
    
    [menu addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    
    [self presentViewController:menu animated:YES completion:nil];
}

- (void)showKeychainList {
    NSArray *items = mfGetKeychainItems();
    
    UIAlertController *list;
    if (items.count == 0) {
        list = [UIAlertController alertControllerWithTitle:@"Keychain 列表"
                                                   message:@"(无 Generic Password 项)"
                                            preferredStyle:UIAlertControllerStyleAlert];
        [list addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            [self showMainMenu];
        }]];
    } else {
        list = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:@"Keychain 列表 (%lu 项)", (unsigned long)items.count]
                                                   message:nil
                                            preferredStyle:UIAlertControllerStyleAlert];
        
        for (NSDictionary *item in items) {
            NSString *summary = mfFormatSummary(item);
            [list addAction:[UIAlertAction actionWithTitle:summary style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [self showKeychainDetail:item];
            }]];
        }
        [list addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
            [self showMainMenu];
        }]];
    }
    
    [self presentViewController:list animated:YES completion:nil];
}

- (void)showKeychainDetail:(NSDictionary *)item {
    NSString *detail = mfFormatDetail(item);
    
    UIAlertController *detailAlert = [UIAlertController alertControllerWithTitle:@"Keychain 详情"
                                                                         message:detail
                                                                  preferredStyle:UIAlertControllerStyleAlert];
    [detailAlert addAction:[UIAlertAction actionWithTitle:@"复制数据" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSData *data = item[(__bridge id)kSecValueData];
        if (data) {
            [[UIPasteboard generalPasteboard] setString:[data base64EncodedStringWithOptions:0]];
        }
    }]];
    [detailAlert addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        [self showKeychainList];
    }]];
    
    [self presentViewController:detailAlert animated:YES completion:nil];
}

- (void)copyKeychainToPasteboard {
    NSArray *items = mfGetKeychainItems();
    if (items.count == 0) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示" message:@"无 Keychain 项可导出" preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    
    NSMutableArray *exportArray = [NSMutableArray array];
    for (NSDictionary *item in items) {
        NSMutableDictionary *exp = [NSMutableDictionary dictionary];
        NSData *data = item[(__bridge id)kSecValueData];
        if (data) exp[@"data"] = [data base64EncodedStringWithOptions:0];
        for (id key in item) {
            if (![key isEqual:(__bridge id)kSecValueData]) exp[key] = item[key];
        }
        [exportArray addObject:exp];
    }
    
    NSError *jsonErr = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:exportArray options:NSJSONWritingPrettyPrinted error:&jsonErr];
    if (jsonErr || !jsonData) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"失败" message:[NSString stringWithFormat:@"JSON 编码失败: %@", jsonErr ?: @"" ] preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    
    NSString *base64 = [jsonData base64EncodedStringWithOptions:0];
    [[UIPasteboard generalPasteboard] setString:base64];
    
    UIAlertController *toast = [UIAlertController alertControllerWithTitle:nil message:[NSString stringWithFormat:@"✅ 已复制到剪贴板 (%lu 项, %lu 字符)", (unsigned long)items.count, (unsigned long)base64.length] preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:toast animated:YES completion:^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            [toast dismissViewControllerAnimated:YES completion:nil];
        });
    }];
}

- (void)showRestorePrompt {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"恢复 Keychain"
                                                                   message:@"粘贴 Base64 编码的 Keychain JSON 数据"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"Base64 JSON";
        tf.font = [UIFont systemFontOfSize:13];
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"恢复" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        UITextField *tf = alert.textFields.firstObject;
        if (tf && tf.text.length > 0) {
            [self startRestoreFromBase64:tf.text];
        }
    }]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)startRestoreFromBase64:(NSString *)base64 {
    self.loadingAlert = [UIAlertController alertControllerWithTitle:nil message:@"正在恢复…" preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:self.loadingAlert animated:YES completion:nil];
    
    [self performSelectorInBackground:@selector(doRestoreInBackground:) withObject:base64];
}

- (void)doRestoreInBackground:(NSString *)base64 {
    NSData *jsonData = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
    if (!jsonData) {
        self.restoreSuccess = NO;
        self.restoreResultMessage = @"Base64 解码失败";
        [self performSelectorOnMainThread:@selector(showRestoreResult) withObject:nil waitUntilDone:NO];
        return;
    }
    
    NSError *jsonErr = nil;
    NSArray *importArray = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&jsonErr];
    if (jsonErr || !importArray) {
        self.restoreSuccess = NO;
        self.restoreResultMessage = [NSString stringWithFormat:@"JSON 解析失败: %@", jsonErr ?: @"" ];
        [self performSelectorOnMainThread:@selector(showRestoreResult) withObject:nil waitUntilDone:NO];
        return;
    }
    
    NSUInteger successCount = 0, failCount = 0;
    for (NSDictionary *item in importArray) {
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
        if (status == errSecSuccess) {
            successCount++;
        } else if (status == errSecDuplicateItem) {
            NSDictionary *updQuery = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecAttrAccount: item[(__bridge id)kSecAttrAccount] ?: @"",
                (__bridge id)kSecAttrService: item[(__bridge id)kSecAttrService] ?: @""
            };
            NSDictionary *updAttrs = @{ (__bridge id)kSecValueData: data ?: [NSData data] };
            if (SecItemUpdate((__bridge CFDictionaryRef)updQuery, (__bridge CFDictionaryRef)updAttrs) == errSecSuccess) {
                successCount++;
            } else failCount++;
        } else failCount++;
    }
    
    self.restoreSuccess = YES;
    self.restoreResultMessage = [NSString stringWithFormat:@"成功: %lu\n失败: %lu", (unsigned long)successCount, (unsigned long)failCount];
    [self performSelectorOnMainThread:@selector(showRestoreResult) withObject:nil waitUntilDone:NO];
}

- (void)showRestoreResult {
    [self.loadingAlert dismissViewControllerAnimated:YES completion:^{
        NSString *title = self.restoreSuccess ? @"恢复完成" : @"失败";
        UIAlertController *result = [UIAlertController alertControllerWithTitle:title
                                                                        message:self.restoreResultMessage
                                                                 preferredStyle:UIAlertControllerStyleAlert];
        [result addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            [self showMainMenu];
        }]];
        [self presentViewController:result animated:YES completion:nil];
    }];
}

@end