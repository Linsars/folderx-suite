// MFCryptoToolbox.m — 解密工具 v2 (v1.8.0)
// 对标 ToolsEric UCPTCryptoToolboxVC (96 方法)，实现自研、零第三方依赖
// 能力：AES-CBC/ECB/CTR + MD5/SHA 家族 + HMAC + Base64/Hex/URL 编解码 + JWT 解码
// 输入格式解析(文本/hex/base64) + key/IV 自动归一化(hex→base64→utf8 逐级尝试)
// GCM/RSA/SM4 不做：GCM 需 CryptoKit(Swift-only)，RSA 无私钥场景无意义

#import "MFPanel.h"
#import <CommonCrypto/CommonCrypto.h>
// CCPaddingOptions 定义在 SPI 头，手动补齐（符号 libSystem 公开）
typedef uint32_t CCPaddingOptions;
#ifndef ccNoPadding
#define ccNoPadding 0
#endif
#ifndef ccPKCS7Padding
#define ccPKCS7Padding 1
#endif

#pragma mark - 算法表

typedef struct { int id; const char *name; int group; } MFCryptoAlgo;
// group: 0=对称(key+iv) 1=哈希 2=HMAC(key) 3=编解码
static const MFCryptoAlgo mfAlgos[] = {
    {0,  "AES-CBC",     0},
    {1,  "AES-ECB",     0},
    {2,  "AES-CTR",     0},
    {10, "MD5",         1},
    {11, "SHA1",        1},
    {12, "SHA256",      1},
    {13, "SHA512",      1},
    {20, "HMAC-SHA256", 2},
    {21, "HMAC-SHA1",   2},
    {22, "HMAC-MD5",    2},
    {30, "Base64 编码",  3},
    {31, "Base64 解码",  3},
    {32, "Hex 编码",     3},
    {33, "Hex 解码",     3},
    {34, "URL 编码",     3},
    {35, "URL 解码",     3},
    {40, "JWT 解码",     3},
};
static const int mfAlgoCount = sizeof(mfAlgos) / sizeof(mfAlgos[0]);

#pragma mark - 编解码基础

static NSData *mfCryptoUnhex(NSString *s) {
    NSMutableString *h = [s mutableCopy];
    [h replaceOccurrencesOfString:@" " withString:@"" options:0 range:NSMakeRange(0, h.length)];
    [h replaceOccurrencesOfString:@"\n" withString:@"" options:0 range:NSMakeRange(0, h.length)];
    if (!h.length || h.length % 2) return nil;
    NSMutableData *d = [NSMutableData dataWithCapacity:h.length / 2];
    char hex[3] = {0};
    for (NSUInteger i = 0; i + 1 < h.length; i += 2) {
        hex[0] = [h characterAtIndex:i]; hex[1] = [h characterAtIndex:i + 1];
        unsigned int byte;
        if (sscanf(hex, "%02x", &byte) != 1) return nil;
        unsigned char b = (unsigned char)byte;
        [d appendBytes:&b length:1];
    }
    return d;
}

static NSString *mfCryptoToHex(NSData *d) {
    if (!d.length) return @"";
    char *buf = malloc(d.length * 2 + 1);
    if (!buf) return @"";
    for (NSUInteger i = 0; i < d.length; i++) sprintf(buf + i * 2, "%02x", ((const unsigned char *)d.bytes)[i]);
    buf[d.length * 2] = 0;
    NSString *s = [NSString stringWithUTF8String:buf];
    free(buf);
    return s;
}

// key 归一化：hex(≥16字节且合法) → base64(≥16字节) → utf8 原文
static NSData *mfCryptoParseSecret(NSString *s) {
    s = [s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!s.length) return nil;
    NSCharacterSet *nonHex = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet];
    if ([s rangeOfCharacterFromSet:nonHex].location == NSNotFound && s.length >= 32 && s.length % 2 == 0) {
        NSData *hd = mfCryptoUnhex(s);
        if (hd.length >= 16) return hd;
    }
    if (s.length % 4 == 0 && s.length >= 24) {
        NSData *b64 = [[NSData alloc] initWithBase64EncodedString:s options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (b64.length >= 16) return b64;
    }
    return [s dataUsingEncoding:NSUTF8StringEncoding];
}

// IV 归一化：不足补零、超长截断到 blockSize（对标 normalizedIV:blockSize:）
static NSData *mfCryptoNormalizeIV(NSString *s, NSUInteger blockLen) {
    NSMutableData *out = [NSMutableData dataWithLength:blockLen];
    memset(out.mutableBytes, 0, blockLen);
    NSData *iv = mfCryptoParseSecret(s ?: @"");
    if (iv.length) memcpy(out.mutableBytes, iv.bytes, MIN(iv.length, blockLen));
    return out;
}

// 输入解析：0=文本 1=hex 2=base64
static NSData *mfCryptoParseInput(NSString *text, NSInteger fmt) {
    if (!text.length) return nil;
    switch (fmt) {
        case 1: return mfCryptoUnhex(text);
        case 2: return [[NSData alloc] initWithBase64EncodedString:text options:NSDataBase64DecodingIgnoreUnknownCharacters];
        default: return [text dataUsingEncoding:NSUTF8StringEncoding];
    }
}

// 输出条目化 v2.9.5：HEX/BASE64/UTF8 各一条，供左划复制列表
static NSArray *mfCryptoOneEntry(NSString *label, NSString *value) {
    return @[@{@"label": label ?: @"", @"value": value ?: @""}];
}
static NSArray *mfCryptoViewsEntries(NSData *d) {
    if (!d.length) return mfCryptoOneEntry(@"⚠️", @"(空)");
    NSMutableArray *r = [NSMutableArray array];
    [r addObject:@{@"label": @"HEX", @"value": mfCryptoToHex(d)}];
    [r addObject:@{@"label": @"BASE64", @"value": [d base64EncodedStringWithOptions:0]}];
    NSString *utf = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (utf.length)
        [r addObject:@{@"label": @"UTF8", @"value": utf.length > 800 ? [[utf substringToIndex:800] stringByAppendingString:@"…"] : utf}];
    return r;
}

#pragma mark - 运算核心

static NSData *mfCryptoHashData(NSData *in, int algo) {
    unsigned char buf[CC_SHA512_DIGEST_LENGTH];
    const void *data = in.bytes; CC_LONG n = (CC_LONG)in.length;
    switch (algo) {
        case 10: CC_MD5(data, n, buf);  return [NSData dataWithBytes:buf length:CC_MD5_DIGEST_LENGTH];
        case 11: CC_SHA1(data, n, buf); return [NSData dataWithBytes:buf length:CC_SHA1_DIGEST_LENGTH];
        case 12: CC_SHA256(data, n, buf); return [NSData dataWithBytes:buf length:CC_SHA256_DIGEST_LENGTH];
        default: CC_SHA512(data, n, buf); return [NSData dataWithBytes:buf length:CC_SHA512_DIGEST_LENGTH];
    }
}

static NSData *mfCryptoHmac(NSData *in, NSData *key, int algo) {
    CCHmacAlgorithm alg;
    NSUInteger dlen;
    switch (algo) {
        case 20: alg = kCCHmacAlgSHA256; dlen = CC_SHA256_DIGEST_LENGTH; break;
        case 21: alg = kCCHmacAlgSHA1;   dlen = CC_SHA1_DIGEST_LENGTH;   break;
        default: alg = kCCHmacAlgMD5;    dlen = CC_MD5_DIGEST_LENGTH;    break;
    }
    unsigned char buf[64];
    CCHmac(alg, key.bytes, key.length, in.bytes, in.length, buf);
    return [NSData dataWithBytes:buf length:dlen];
}

// 对称：CBC/ECB 用 PKCS7，CTR 无填充流式
static NSData *mfCryptoSymmetric(NSData *in, NSData *key, NSData *iv, int algo, BOOL encrypt, NSString **errOut) {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
        *errOut = @"Key 须为 16/24/32 字节（输入框支持 hex/base64/utf8 自动识别）";
        return nil;
    }
    CCMode mode = algo == 0 ? kCCModeCBC : (algo == 1 ? kCCModeECB : kCCModeCTR);
    CCPaddingOptions pad = (algo == 2) ? ccNoPadding : ccPKCS7Padding;
    CCCryptorRef ref = NULL;
    CCCryptorStatus st = CCCryptorCreateWithMode(encrypt ? kCCEncrypt : kCCDecrypt, mode, kCCAlgorithmAES,
        pad, iv.length ? iv.bytes : NULL, key.bytes, key.length, NULL, 0, 0, 0, &ref);
    if (st != kCCSuccess || !ref) { *errOut = [NSString stringWithFormat:@"初始化失败 status=%d", st]; return nil; }
    NSMutableData *out = [NSMutableData dataWithLength:in.length + kCCBlockSizeAES128 + 16];
    size_t moved = 0, total = 0;
    st = CCCryptorUpdate(ref, in.bytes, in.length, out.mutableBytes, out.length, &moved);
    total += moved;
    if (st == kCCSuccess) {
        st = CCCryptorFinal(ref, (char *)out.mutableBytes + total, out.length - total, &moved);
        total += moved;
    }
    CCCryptorRelease(ref);
    if (st != kCCSuccess) { *errOut = [NSString stringWithFormat:@"运算失败 status=%d（key 错误或数据非块对齐）", st]; return nil; }
    out.length = total;
    return out;
}

static NSString *mfCryptoJwtDecode(NSString *token) {
    token = [token stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSArray *parts = [token componentsSeparatedByString:@"."];
    if (parts.count < 2) return @"⚠️ JWT 格式错误（header.payload[.signature]）";
    NSMutableString *r = [NSMutableString string];
    NSArray *names = @[@"HEADER", @"PAYLOAD"];
    for (NSUInteger i = 0; i < 2 && i < parts.count; i++) {
        NSString *seg = parts[i];
        seg = [seg stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
        seg = [seg stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
        while (seg.length % 4) seg = [seg stringByAppendingString:@"="];
        NSData *d = [[NSData alloc] initWithBase64EncodedString:seg options:NSDataBase64DecodingIgnoreUnknownCharacters];
        NSString *json = d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
        [r appendFormat:@"【%@】\n%@\n\n", names[i], json ?: @"⚠️ 解码失败"];
    }
    if (parts.count > 2) [r appendFormat:@"【SIGNATURE】\n%@\n(签名校验需密钥)", parts[2]];
    return r;
}

#pragma mark - 执行分发

static NSArray *mfCryptoExecuteE(int algo, NSInteger inFmt, BOOL encrypt,
                                 NSString *inputText, NSString *keyText, NSString *ivText) {
    NSData *in = mfCryptoParseInput(inputText, inFmt);
    if (!in.length && algo != 40) return mfCryptoOneEntry(@"⚠️", @"输入为空或格式解析失败");

    // 编解码组（输入本身就是编码文本，不做二次解析）
    switch (algo) {
        case 30: return mfCryptoOneEntry(@"Base64", [in base64EncodedStringWithOptions:0]);
        case 31: {
            NSData *d = [[NSData alloc] initWithBase64EncodedString:[[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding] ?: @"" options:NSDataBase64DecodingIgnoreUnknownCharacters];
            return d.length ? mfCryptoViewsEntries(d) : mfCryptoOneEntry(@"⚠️", @"Base64 解析失败");
        }
        case 32: return mfCryptoOneEntry(@"Hex", mfCryptoToHex(in));
        case 33: {
            NSData *d = mfCryptoUnhex([[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding] ?: @"");
            return d.length ? mfCryptoViewsEntries(d) : mfCryptoOneEntry(@"⚠️", @"Hex 解析失败");
        }
        case 34: {
            NSString *s = [[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding] ?: @"";
            return mfCryptoOneEntry(@"URL", [s stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]] ?: @"⚠️ 编码失败");
        }
        case 35: {
            NSString *s = [[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding] ?: @"";
            return mfCryptoOneEntry(@"URL", [s stringByRemovingPercentEncoding] ?: @"⚠️ 解码失败");
        }
        case 40: return mfCryptoOneEntry(@"JWT", mfCryptoJwtDecode([[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding] ?: @""));
    }

    // 哈希组
    if (algo >= 10 && algo <= 13) return mfCryptoViewsEntries(mfCryptoHashData(in, algo));

    // HMAC 组
    if (algo >= 20 && algo <= 22) {
        NSData *key = mfCryptoParseSecret(keyText ?: @"");
        if (!key.length) return mfCryptoOneEntry(@"⚠️", @"请填 Key");
        return mfCryptoViewsEntries(mfCryptoHmac(in, key, algo));
    }

    // 对称组
    NSData *key = mfCryptoParseSecret(keyText ?: @"");
    if (!key.length) return mfCryptoOneEntry(@"⚠️", @"请填 Key");
    NSData *iv = mfCryptoNormalizeIV(ivText, kCCBlockSizeAES128);
    NSString *err = nil;
    NSData *out = mfCryptoSymmetric(in, key, iv, algo, encrypt, &err);
    if (!out) return mfCryptoOneEntry(@"⚠️", [NSString stringWithFormat:@"%@", err ?: @"失败"]);
    return mfCryptoViewsEntries(out);
}

#pragma mark - 页面

// v2.9.4: 输入框真 placeholder 管理（UITextView 不会在输入时自动换 textColor，
// 旧写法「textColor 指针当标记」导致执行时永远把输入当占位符 → inlen=0）
static NSString * const kMFCryptoPH = @"在此粘贴要处理的内容…";
@interface MFCryptoPHDel : NSObject <UITextViewDelegate> @end
@implementation MFCryptoPHDel
- (void)textViewDidBeginEditing:(UITextView *)tv {
    if ([tv.text isEqualToString:kMFCryptoPH]) { tv.text = @""; tv.textColor = UIColor.labelColor; }
}
- (void)textViewDidEndEditing:(UITextView *)tv {
    if (!tv.text.length) { tv.text = kMFCryptoPH; tv.textColor = [UIColor placeholderTextColor]; }
}
@end
static NSObject<UITextViewDelegate> *g_mfCryptoInputDel(void) {
    static MFCryptoPHDel *d = nil;
    return d ?: (d = [MFCryptoPHDel new]);
}

// v2.9.5: 结果条目列表 — 左划复制 / 点行复制
@interface MFCryptoResList : NSObject <UITableViewDataSource, UITableViewDelegate> @end
@implementation MFCryptoResList
- (NSArray *)entriesFor:(UITableView *)tv { return objc_getAssociatedObject(tv.superview, "entries"); }
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return [self entriesFor:tv].count; }
- (CGFloat)tableView:(UITableView *)tv heightForRowAtIndexPath:(NSIndexPath *)ip {
    NSArray *hs = objc_getAssociatedObject(tv.superview, "rowHs");
    return (ip.row < (NSInteger)hs.count) ? [hs[ip.row] floatValue] : 44;
}
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *rid = @"MFCryptoRes";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:rid];
    if (!c) {
        c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:rid];
        c.backgroundColor = UIColor.clearColor;
        c.selectionStyle = UITableViewCellSelectionStyleNone;
        UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(12, 7, 80, 14)];
        lb.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightSemibold];
        lb.textColor = [UIColor secondaryLabelColor];
        lb.tag = 1;
        [c.contentView addSubview:lb];
        UILabel *v = [[UILabel alloc] initWithFrame:CGRectMake(12, 23, 100, 16)];
        v.font = [UIFont fontWithName:@"Menlo-Regular" size:10] ?: [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
        v.textColor = UIColor.labelColor;
        v.numberOfLines = 8;
        v.tag = 2;
        [c.contentView addSubview:v];
    }
    NSArray *e = [self entriesFor:tv];
    if (ip.row >= (NSInteger)e.count) return c;
    NSDictionary *d = e[ip.row];
    UILabel *lb = [c.contentView viewWithTag:1];
    UILabel *v = [c.contentView viewWithTag:2];
    lb.text = d[@"label"];
    v.text = d[@"value"];
    CGFloat rowH = [self tableView:tv heightForRowAtIndexPath:ip];
    v.frame = CGRectMake(12, 23, tv.bounds.size.width - 24, rowH - 27);
    return c;
}
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSArray *e = [self entriesFor:tv];
    if (ip.row >= (NSInteger)e.count) return nil;
    NSString *val = e[ip.row][@"value"];
    __weak UITableView *wtv = tv;
    UIContextualAction *a = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal title:@"📋 复制" handler:^(UIContextualAction *act, UIView *sv, void (^done)(BOOL)) {
        mfCopyText(val, nil);
        done(YES);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [wtv setEditing:NO animated:YES];
        });
    }];
    a.backgroundColor = [UIColor systemIndigoColor];
    UISwipeActionsConfiguration *cfg = [UISwipeActionsConfiguration configurationWithActions:@[a]];
    cfg.performsFirstActionWithFullSwipe = NO;
    return cfg;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    NSArray *e = [self entriesFor:tv];
    if (ip.row < (NSInteger)e.count) mfCopyText(e[ip.row][@"value"], nil);
}
@end
static NSObject<UITableViewDataSource, UITableViewDelegate> *g_mfCryptoResList(void) {
    static MFCryptoResList *l = nil;
    return l ?: (l = [MFCryptoResList new]);
}

void mfShowCryptoToolboxPage(void) {
    UIView *page = mfMakePage(@"🔐 解密工具箱", YES);
    CGFloat w = g_mfCardW;

    UITextView *input = [[UITextView alloc] initWithFrame:CGRectMake(12, 44, w - 24, 54)];
    input.font = [UIFont systemFontOfSize:12];
    input.backgroundColor = [UIColor secondarySystemBackgroundColor];
    input.layer.cornerRadius = 10;
    input.autocorrectionType = UITextAutocorrectionTypeNo;
    input.text = @"在此粘贴要处理的内容…";
    input.textColor = [UIColor placeholderTextColor];
    input.delegate = g_mfCryptoInputDel();
    mfAttachKbBar(input);   // v2.7.1: 键盘收起工具条
    [page addSubview:input];

    UISegmentedControl *fmtSeg = [[UISegmentedControl alloc] initWithItems:@[@"文本", @"Hex", @"Base64"]];
    fmtSeg.frame = CGRectMake(12, 102, w - 24, 30);
    fmtSeg.selectedSegmentIndex = 0;
    fmtSeg.apportionsSegmentWidthsByContent = YES;
    [page addSubview:fmtSeg];

    // v2.9.1: 算法选择内嵌化 — 分组 segment + 横滑 chip，替代 action sheet 弹窗
    UISegmentedControl *grpSeg = [[UISegmentedControl alloc] initWithItems:@[@"对称", @"哈希", @"HMAC", @"编解码"]];
    grpSeg.frame = CGRectMake(12, 138, w - 24, 30);
    grpSeg.selectedSegmentIndex = 0;
    [page addSubview:grpSeg];

    UIScrollView *chipScroll = [[UIScrollView alloc] initWithFrame:CGRectMake(12, 174, w - 24, 32)];
    chipScroll.showsHorizontalScrollIndicator = NO;
    [page addSubview:chipScroll];

    // v2.9.3: 对称组 加密/解密 方向（此前 encrypt 硬编码 YES，解密不可达）
    UISegmentedControl *dirSeg = [[UISegmentedControl alloc] initWithItems:@[@"加密", @"解密"]];
    dirSeg.frame = CGRectMake(w - 134, 138, 122, 30);
    dirSeg.selectedSegmentIndex = 0;
    [page addSubview:dirSeg];
    objc_setAssociatedObject(page, "dirSeg", dirSeg, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    UITextField *keyF = [[UITextField alloc] initWithFrame:CGRectZero];
    keyF.placeholder = @"Key（hex / base64 / 文本自动识别）";
    keyF.font = [UIFont systemFontOfSize:12];
    keyF.borderStyle = UITextBorderStyleRoundedRect;
    keyF.autocorrectionType = UITextAutocorrectionTypeNo;
    mfAttachKbBar(keyF);   // v2.7.1: 键盘收起工具条
    [page addSubview:keyF];

    UITextField *ivF = [[UITextField alloc] initWithFrame:CGRectZero];
    ivF.placeholder = @"IV / Nonce（不足补零，可空）";
    ivF.font = [UIFont systemFontOfSize:12];
    ivF.borderStyle = UITextBorderStyleRoundedRect;
    ivF.autocorrectionType = UITextAutocorrectionTypeNo;
    mfAttachKbBar(ivF);   // v2.7.1: 键盘收起工具条
    [page addSubview:ivF];

    UIButton *runBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    runBtn.frame = CGRectMake(12, 258, w - 24, 38);
    runBtn.backgroundColor = [UIColor systemGreenColor];
    runBtn.layer.cornerRadius = 10;
    runBtn.tintColor = UIColor.whiteColor;
    runBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    [runBtn setTitle:@"▶ 执行" forState:UIControlStateNormal];
    [page addSubview:runBtn];

    UITableView *resTable = [[UITableView alloc] initWithFrame:CGRectMake(12, 322, w - 24, g_mfCardH - 372) style:UITableViewStylePlain];
    resTable.backgroundColor = [UIColor secondarySystemBackgroundColor];
    resTable.layer.cornerRadius = 10;
    resTable.clipsToBounds = YES;
    resTable.dataSource = g_mfCryptoResList();
    resTable.delegate = g_mfCryptoResList();
    resTable.keyboardDismissMode = UIScrollViewKeyboardDismissModeInteractive;
    [page addSubview:resTable];

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(16, 300, w - 32, 14)];
    status.font = [UIFont systemFontOfSize:10];
    status.textColor = [UIColor secondaryLabelColor];
    [page addSubview:status];

    // 布局函数：编解码组隐藏 Key/IV；对称组收缩分组条并显示 加密/解密
    void (^relayout)(void) = ^{
        BOOL codec = (grpSeg.selectedSegmentIndex == 3);
        BOOL sym = (grpSeg.selectedSegmentIndex == 0);
        // v2.9.5: 编解码组隐藏输入格式条（编码/解码本身就是格式，fmt 二次解析=解两次）
        fmtSeg.hidden = codec;
        CGFloat top = codec ? 102 : 138;
        dirSeg.hidden = !sym;
        grpSeg.frame = CGRectMake(12, top, sym ? w - 158 : w - 24, 30);
        if (sym) dirSeg.frame = CGRectMake(w - 134, top, 122, 30);
        chipScroll.frame = CGRectMake(12, top + 36, w - 24, 32);
        CGFloat y = top + 74;
        keyF.hidden = codec; ivF.hidden = codec;
        if (!codec) {
            keyF.frame = CGRectMake(12, y, w - 24, 34); y += 40;
            ivF.frame  = CGRectMake(12, y, w - 24, 34); y += 40;
        }
        runBtn.frame  = CGRectMake(12, y, w - 24, 38); y += 44;
        status.frame  = CGRectMake(16, y, w - 32, 14); y += 18;
        resTable.frame = CGRectMake(12, y, w - 24, g_mfCardH - y - 12);
    };

    objc_setAssociatedObject(page, "input", input, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "fmtSeg", fmtSeg, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "grpSeg", grpSeg, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "keyF", keyF, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "ivF", ivF, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "resTable", resTable, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "status", status, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    extern void mfCryptoBuildChips(UIScrollView *scroll, int group);
    objc_setAssociatedObject(page, "chipScroll", chipScroll, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    mfCryptoBuildChips(chipScroll, 0);
    relayout();

    [grpSeg addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoGroupChanged:") forControlEvents:UIControlEventValueChanged];
    objc_setAssociatedObject(grpSeg, "relayout", relayout, OBJC_ASSOCIATION_COPY_NONATOMIC);
    [runBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoRun:") forControlEvents:UIControlEventTouchUpInside];

    mfPushPage(page);
}

// ===== v2.9.1: 内嵌算法选择（替代 action sheet 弹窗）=====
static int g_mfCryptoAlgo = 0;   // 当前算法 id（文件级状态，页面重建时复位）

static void mfCryptoHighlightChips(UIScrollView *scroll) {
    for (UIView *v in scroll.subviews) {
        if (![v isKindOfClass:[UIButton class]]) continue;
        UIButton *b = (UIButton *)v;
        BOOL sel = (b.tag == (NSUInteger)g_mfCryptoAlgo);
        b.backgroundColor = sel ? [UIColor systemIndigoColor] : [UIColor secondarySystemFillColor];
        [b setTitleColor:sel ? UIColor.whiteColor : UIColor.labelColor forState:UIControlStateNormal];
    }
}

void mfCryptoBuildChips(UIScrollView *scroll, int group) {
    for (UIView *sub in scroll.subviews) [sub removeFromSuperview];
    CGFloat x = 0;
    for (int i = 0; i < mfAlgoCount; i++) {
        if (mfAlgos[i].group != group) continue;
        NSString *nm = @(mfAlgos[i].name);
        CGFloat cw = [nm sizeWithAttributes:@{NSFontAttributeName: [UIFont systemFontOfSize:12]}].width + 24;
        UIButton *chip = [UIButton buttonWithType:UIButtonTypeSystem];
        chip.frame = CGRectMake(x, 3, cw, 26);
        chip.layer.cornerRadius = 13;
        chip.titleLabel.font = [UIFont systemFontOfSize:12];
        chip.tag = mfAlgos[i].id;
        [chip setTitle:nm forState:UIControlStateNormal];
        [chip addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoChipTapped:") forControlEvents:UIControlEventTouchUpInside];
        [scroll addSubview:chip];
        x += cw + 8;
    }
    scroll.contentSize = CGSizeMake(MAX(x - 8, 10), 32);
    mfCryptoHighlightChips(scroll);
}

void mfCryptoGroupChangedAction(UISegmentedControl *seg) {
    UIView *page = (UIView *)seg.superview;
    UIScrollView *scroll = objc_getAssociatedObject(page, "chipScroll");
    if (!scroll) return;
    int group = (int)seg.selectedSegmentIndex;
    for (int i = 0; i < mfAlgoCount; i++) {
        if (mfAlgos[i].group == group) { g_mfCryptoAlgo = mfAlgos[i].id; break; }
    }
    mfCryptoBuildChips(scroll, group);
    void (^relayout)(void) = objc_getAssociatedObject(seg, "relayout");
    if (relayout) relayout();
}

void mfCryptoChipTappedAction(UIButton *chip) {
    g_mfCryptoAlgo = (int)chip.tag;
    mfCryptoHighlightChips((UIScrollView *)chip.superview);
}

void mfCryptoRunAction(UIButton *btn) {
    UIView *page = (UIView *)btn.superview;
    UITextView *input = objc_getAssociatedObject(page, "input");
    UISegmentedControl *fmtSeg = objc_getAssociatedObject(page, "fmtSeg");
    UITextField *keyF = objc_getAssociatedObject(page, "keyF");
    UITextField *ivF = objc_getAssociatedObject(page, "ivF");
    UITableView *resTable = objc_getAssociatedObject(page, "resTable");
    UILabel *status = objc_getAssociatedObject(page, "status");
    if (!input || !resTable) return;
    int algo = g_mfCryptoAlgo;
    const MFCryptoAlgo *sa = NULL;
    for (int i = 0; i < mfAlgoCount; i++) if (mfAlgos[i].id == algo) { sa = &mfAlgos[i]; break; }
    UISegmentedControl *dirSeg = objc_getAssociatedObject(page, "dirSeg");
    BOOL encrypt = dirSeg ? (dirSeg.selectedSegmentIndex == 0) : YES;
    // 占位符文本当空处理
    // v2.9.4: 按「字符串 == placeholder」判定空输入（textColor 指针比较不可靠）
    NSString *txt = [input.text isEqualToString:kMFCryptoPH] ? @"" : (input.text ?: @"" );
    NSInteger fmt = fmtSeg ? fmtSeg.selectedSegmentIndex : 0;
    if (sa && sa->group == 3) fmt = 0; // v2.9.5: 编解码组输入本身就是编码文本，禁二次解析
    NSArray *entries = mfCryptoExecuteE(algo, fmt, encrypt, txt, keyF.text, ivF.text);
    // 行高按内容算（monospace 10pt ≈ 6pt/字符，最多 8 行）
    NSMutableArray *hs = [NSMutableArray array];
    CGFloat perLine = MAX((g_mfCardW - 100) / 6.0, 20);
    for (NSDictionary *e in entries) {
        NSUInteger lines = MAX(1, (NSUInteger)ceil([(e[@"value"] ?: @"") length] / perLine));
        lines = MIN(lines, (NSUInteger)8);
        [hs addObject:@(MAX(lines * 13 + 27, 44))];
    }
    objc_setAssociatedObject(page, "entries", entries, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "rowHs", hs, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    status.text = [NSString stringWithFormat:@"算法: %s · 输入 %lu 字符 · 左划或点按复制", sa ? sa->name : "?", (unsigned long)txt.length];
    [resTable reloadData];
    mfLog(@"[MF] crypto run algo=%d fmt=%ld enc=%d inlen=%lu rows=%lu",
          algo, (long)fmt, encrypt, (unsigned long)txt.length, (unsigned long)entries.count);
}


