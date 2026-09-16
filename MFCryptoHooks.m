// MFCryptoHooks.m — T1: 解密捕获（对标 ToolsEric UCDecryptTool 8 方法）
// MSHookFunction 运行时 dlsym 解析（ellekit 注入进程后存在；编译期不依赖 substrate 头）
// Hook: CCCrypt / CCCryptorCreate(CreateWithMode) / Update / Final / CCHmac / CC_MD5/SHA*
// 开关: pref "mfCryptoCapture"；关=纯透传零开销路径

#import "MFPanel.h"
#import <CommonCrypto/CommonCrypto.h>
#import <dlfcn.h>
#import <objc/runtime.h>

typedef uint32_t CCPaddingOptionsT;  // 老 SDK SPI 常量手动补（v1.8.0 已验证）

#pragma mark - 捕获记录模型

@interface MFCryptoRecord : NSObject
@property (copy) NSString *kind;    // AES-CBC / HMAC-SHA256 / MD5 ...
@property (copy) NSString *dir;     // 加密/解密/流式/HMAC/摘要
@property (copy) NSString *keyHex;
@property (copy) NSString *ivHex;
@property (strong) NSData *input;
@property (strong) NSData *output;
@property (strong) NSDate *ts;
@end
@implementation MFCryptoRecord @end

static NSMutableArray *g_cryptoRecs = nil;
static BOOL g_cryptoHookInstalled = NO;

BOOL mfCryptoEnabledState(void) {
    return mfPrefBool(@"mfCryptoCapture", NO);
}

static void mfCryptoRecord(MFCryptoRecord *r) {
    if (!g_cryptoRecs) g_cryptoRecs = [NSMutableArray new];
    @synchronized (g_cryptoRecs) {
        [g_cryptoRecs addObject:r];
        if (g_cryptoRecs.count > 100) [g_cryptoRecs removeObjectAtIndex:0];
    }
}

NSArray *mfCryptoRecordsSnapshot(void) {
    if (!g_cryptoRecs) return @[];
    @synchronized (g_cryptoRecs) { return [g_cryptoRecs copy]; }
}

static NSString *mfHex(NSData *d, NSUInteger cap) {
    if (!d || d.length == 0) return @"(空)";
    NSUInteger n = MIN(d.length, cap);
    NSMutableString *s = [NSMutableString stringWithCapacity:n * 2];
    const unsigned char *b = d.bytes;
    for (NSUInteger i = 0; i < n; i++) [s appendFormat:@"%02x", b[i]];
    if (d.length > cap) [s appendFormat:@"…(+%luB)", (unsigned long)(d.length - cap)];
    return s;
}
static NSString *mfTryUtf8(NSData *d) {
    if (!d || d.length == 0) return nil;
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (!s) return nil;
    unichar printable = 0;
    for (NSUInteger i = 0; i < s.length && i < 64; i++)
        if ([s characterAtIndex:i] >= 32 && [s characterAtIndex:i] != 127) printable++;
    if (printable * 100 / MIN((NSUInteger)64, s.length) < 70) return nil;
    return s.length > 200 ? [[s substringToIndex:200] stringByAppendingString:@"…"] : s;
}

#pragma mark - 流式上下文映射（CCCryptorRef -> key/iv/out）

static NSMutableDictionary *g_streamMap = nil;
static NSString *mfCtxKey(void *ctx) { return [NSString stringWithFormat:@"%p", ctx]; }

#pragma mark - 原函数指针

static CCCryptorStatus (*o_CCCrypt)(CCOperation, CCAlgorithm, CCOptions, const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *);
static CCCryptorStatus (*o_CCCryptorCreate)(CCOperation, CCAlgorithm, CCPaddingOptionsT, const void *, size_t, const void *, CCCryptorRef *);
static CCCryptorStatus (*o_CCCryptorCreateWithMode)(CCOperation, CCMode, CCAlgorithm, CCPaddingOptionsT, const void *, const void *, size_t, const void *, size_t, int, CCModeOptions, CCCryptorRef *);
static CCCryptorStatus (*o_CCCryptorUpdate)(CCCryptorRef, const void *, size_t, void *, size_t, size_t *);
static CCCryptorStatus (*o_CCCryptorFinal)(CCCryptorRef, void *, size_t, size_t *);
static void (*o_CCHmac)(CCHmacAlgorithm, const void *, size_t, const void *, size_t, void *);

// ====== OpenSSL EVP（Python hashlib / libcrypto 路径——v1.9.5）======
typedef void OpaqueEVPCTX; typedef void OpaqueEVPMD;
static int (*o_EVP_EncryptUpdate)(OpaqueEVPCTX *, unsigned char *, int *, const unsigned char *, int);
static int (*o_EVP_DecryptUpdate)(OpaqueEVPCTX *, unsigned char *, int *, const unsigned char *, int);
static int (*o_EVP_CipherUpdate)(OpaqueEVPCTX *, unsigned char *, int *, const unsigned char *, int);
static unsigned char *(*o_OSSLHMAC)(const OpaqueEVPMD *, const void *, int, const unsigned char *, size_t, unsigned char *, unsigned int *);

static void mfRecordOSSLCrypto(NSString *dir, NSData *in, NSData *out) {
    if (!mfCryptoEnabledState()) return;
    @autoreleasepool {
        MFCryptoRecord *r = [MFCryptoRecord new];
        r.kind = @"OpenSSL";
        r.dir = dir;
        r.keyHex = @"(ctx 内部)";
        r.ivHex = @"-";
        r.input = in;
        r.output = out;
        r.ts = [NSDate date];
        mfCryptoRecord(r);
    }
}
static int my_EVP_EncryptUpdate(OpaqueEVPCTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
    int rc = o_EVP_EncryptUpdate(ctx, out, outl, in, inl);
    if (rc == 1 && mfCryptoEnabledState())
        mfRecordOSSLCrypto(@"加密", [[NSData alloc] initWithBytes:in length:(NSUInteger)MAX(inl,0)],
                           (outl && *outl > 0) ? [[NSData alloc] initWithBytes:out length:(NSUInteger)*outl] : nil);
    return rc;
}
static int my_EVP_DecryptUpdate(OpaqueEVPCTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
    int rc = o_EVP_DecryptUpdate(ctx, out, outl, in, inl);
    if (rc == 1 && mfCryptoEnabledState())
        mfRecordOSSLCrypto(@"解密", [[NSData alloc] initWithBytes:in length:(NSUInteger)MAX(inl,0)],
                           (outl && *outl > 0) ? [[NSData alloc] initWithBytes:out length:(NSUInteger)*outl] : nil);
    return rc;
}
static int my_EVP_CipherUpdate(OpaqueEVPCTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
    int rc = o_EVP_CipherUpdate(ctx, out, outl, in, inl);
    if (rc == 1 && mfCryptoEnabledState())
        mfRecordOSSLCrypto(@"加解密", [[NSData alloc] initWithBytes:in length:(NSUInteger)MAX(inl,0)],
                           (outl && *outl > 0) ? [[NSData alloc] initWithBytes:out length:(NSUInteger)*outl] : nil);
    return rc;
}
static unsigned char *my_OSSLHMAC(const OpaqueEVPMD *md, const void *key, int keyLen,
                                  const unsigned char *data, size_t dataLen,
                                  unsigned char *mdOut, unsigned int *mdOutLen) {
    unsigned char *rc = o_OSSLHMAC(md, key, keyLen, data, dataLen, mdOut, mdOutLen);
    if (rc && mfCryptoEnabledState() && key) {
        @autoreleasepool {
            MFCryptoRecord *r = [MFCryptoRecord new];
            r.kind = @"OSSL-HMAC";
            r.dir = @"HMAC";
            r.keyHex = mfHex([[NSData alloc] initWithBytes:key length:(NSUInteger)MIN(keyLen, 32)], 32);
            r.input = [[NSData alloc] initWithBytes:data length:dataLen];
            r.output = mdOutLen ? [[NSData alloc] initWithBytes:mdOut length:*mdOutLen] : nil;
            r.ts = [NSDate date];
            mfCryptoRecord(r);
        }
    }
    return rc;
}

static NSString *mfAlgName(CCAlgorithm alg, CCMode mode) {
    NSString *a = alg == kCCAlgorithmAES ? @"AES" : alg == kCCAlgorithm3DES ? @"3DES" : alg == kCCAlgorithmDES ? @"DES" : alg == kCCAlgorithmRC4 ? @"RC4" : alg == kCCAlgorithmCAST ? @"CAST" : alg == kCCAlgorithmBlowfish ? @"Blowfish" : [NSString stringWithFormat:@"alg%d", alg];
    NSString *m = mode == kCCModeECB ? @"ECB" : mode == kCCModeCBC ? @"CBC" : mode == kCCModeCFB ? @"CFB" : mode == kCCModeCTR ? @"CTR" : @"";
    return m.length ? [NSString stringWithFormat:@"%@-%@", a, m] : a;
}

#pragma mark - Hook 实现

static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opts,
                                  const void *key, size_t keyLen, const void *iv,
                                  const void *dataIn, size_t dataInLen,
                                  void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    CCCryptorStatus st = o_CCCrypt(op, alg, opts, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved);
    if (!mfCryptoEnabledState() || !key) return st;
    @autoreleasepool {
        MFCryptoRecord *r = [MFCryptoRecord new];
        r.kind = mfAlgName(alg, opts & kCCOptionECBMode ? kCCModeECB : kCCModeCBC);
        r.dir = op == kCCEncrypt ? @"加密" : @"解密";
        r.keyHex = mfHex([[NSData alloc] initWithBytes:key length:keyLen], 32);
        r.ivHex = iv ? mfHex([[NSData alloc] initWithBytes:iv length:MIN(keyLen == 24 ? 8 : 16, (NSUInteger)16)], 16) : @"(无)";
        r.input = [[NSData alloc] initWithBytes:dataIn length:dataInLen];
        if (dataOutMoved && *dataOutMoved > 0) r.output = [[NSData alloc] initWithBytes:dataOut length:*dataOutMoved];
        r.ts = [NSDate date];
        mfCryptoRecord(r);
        mfLog(@"[crypto] %@ %@ in=%luB out=%luB", r.dir, r.kind, (unsigned long)dataInLen, dataOutMoved ? (unsigned long)*dataOutMoved : 0);
    }
    return st;
}

static CCCryptorStatus my_CCCryptorCreate(CCOperation op, CCAlgorithm alg, CCPaddingOptionsT pad,
                                          const void *key, size_t keyLen, const void *iv, CCCryptorRef *ref) {
    CCCryptorStatus st = o_CCCryptorCreate(op, alg, pad, key, keyLen, iv, ref);
    if (st == 0 && ref && *ref && key && mfCryptoEnabledState()) {
        @synchronized (g_streamMap) {
            NSMutableDictionary *info = [NSMutableDictionary new];
            info[@"alg"] = mfAlgName(alg, kCCModeCBC);
            info[@"op"] = op == kCCEncrypt ? @"加密" : @"解密";
            info[@"key"] = mfHex([[NSData alloc] initWithBytes:key length:keyLen], 32);
            if (iv) info[@"iv"] = mfHex([[NSData alloc] initWithBytes:iv length:16], 16);
            info[@"out"] = [NSMutableData new];
            g_streamMap[mfCtxKey((void *)*ref)] = info;
        }
    }
    return st;
}

static CCCryptorStatus my_CCCryptorUpdate(CCCryptorRef ref, const void *dataIn, size_t dataInLen,
                                          void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    CCCryptorStatus st = o_CCCryptorUpdate(ref, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved);
    if (st == 0 && dataOutMoved && *dataOutMoved > 0 && mfCryptoEnabledState()) {
        @synchronized (g_streamMap) {
            NSMutableDictionary *info = g_streamMap[mfCtxKey((void *)ref)];
            if (info) [info[@"out"] appendBytes:dataOut length:MIN(*dataOutMoved, (size_t)65536)];
        }
    }
    return st;
}

static CCCryptorStatus my_CCCryptorFinal(CCCryptorRef ref, void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    CCCryptorStatus st = o_CCCryptorFinal(ref, dataOut, dataOutAvail, dataOutMoved);
    NSString *k = mfCtxKey((void *)ref);
    @synchronized (g_streamMap) {
        NSMutableDictionary *info = g_streamMap[k];
        if (info && mfCryptoEnabledState()) {
            if (dataOutMoved && *dataOutMoved > 0) [info[@"out"] appendBytes:dataOut length:MIN(*dataOutMoved, (size_t)65536)];
            MFCryptoRecord *r = [MFCryptoRecord new];
            r.kind = info[@"alg"];
            r.dir = [@"流式·" stringByAppendingString:info[@"op"]];
            r.keyHex = info[@"key"];
            r.ivHex = info[@"iv"] ?: @"(无)";
            r.output = info[@"out"];
            r.ts = [NSDate date];
            mfCryptoRecord(r);
            [g_streamMap removeObjectForKey:k];
        } else if (info) {
            [g_streamMap removeObjectForKey:k];
        }
    }
    return st;
}

static void my_CCHmac(CCHmacAlgorithm alg, const void *key, size_t keyLen,
                      const void *data, size_t dataLen, void *macOut) {
    o_CCHmac(alg, key, keyLen, data, dataLen, macOut);
    if (!mfCryptoEnabledState() || !key) return;
    @autoreleasepool {
        MFCryptoRecord *r = [MFCryptoRecord new];
        NSString *a = alg == kCCHmacAlgSHA256 ? @"HMAC-SHA256" : alg == kCCHmacAlgSHA1 ? @"HMAC-SHA1" : alg == kCCHmacAlgMD5 ? @"HMAC-MD5" : alg == kCCHmacAlgSHA384 ? @"HMAC-SHA384" : alg == kCCHmacAlgSHA512 ? @"HMAC-SHA512" : @"HMAC";
        r.kind = a;
        r.dir = @"HMAC";
        r.keyHex = mfHex([[NSData alloc] initWithBytes:key length:keyLen], 32);
        r.input = [[NSData alloc] initWithBytes:data length:dataLen];
        size_t macLen = alg == kCCHmacAlgSHA1 ? 20 : alg == kCCHmacAlgMD5 ? 16 : alg == kCCHmacAlgSHA256 ? 32 : alg == kCCHmacAlgSHA384 ? 48 : 64;
        r.output = [[NSData alloc] initWithBytes:macOut length:macLen];
        r.ts = [NSDate date];
        mfCryptoRecord(r);
    }
}

static CCCryptorStatus my_CCCryptorCreateWithMode(CCOperation op, CCMode mode, CCAlgorithm alg, CCPaddingOptionsT pad,
                                                  const void *iv, const void *key, size_t keyLen,
                                                  const void *tweak, size_t tweakLen, int numRounds,
                                                  CCModeOptions options, CCCryptorRef *ref) {
    CCCryptorStatus st = o_CCCryptorCreateWithMode(op, mode, alg, pad, iv, key, keyLen, tweak, tweakLen, numRounds, options, ref);
    if (st == 0 && ref && *ref && key && mfCryptoEnabledState()) {
        @synchronized (g_streamMap) {
            NSMutableDictionary *info = [NSMutableDictionary new];
            info[@"alg"] = mfAlgName(alg, mode);
            info[@"op"] = op == kCCEncrypt ? @"加密" : @"解密";
            info[@"key"] = mfHex([[NSData alloc] initWithBytes:key length:keyLen], 32);
            if (iv) info[@"iv"] = mfHex([[NSData alloc] initWithBytes:iv length:MIN(keyLen, (size_t)16)], 16);
            info[@"out"] = [NSMutableData new];
            g_streamMap[mfCtxKey((void *)*ref)] = info;
        }
    }
    return st;
}

#pragma mark - 安装（mini-fishhook GOT 重绑，零外部依赖）

// App 对系统 C 函数(CCCrypt 等)的调用全部经 __DATA/__DATA_CONST 符号指针槽位，
// 改槽位即 hook——不依赖 MSHookFunction/ellekit 符号导出。
// v1.9.3 修复根因：dlsym(RTLD_DEFAULT,"MSHookFunction") 在 ellekit rootless 下搜不到，捕获从未生效。

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>

// 自定义结构体——<mach-o/dyld.h> 与 modules 的 nlist_64 冲突是老坑，全部手写
typedef struct { uint32_t n_strx; uint8_t n_type; uint8_t n_sect; uint16_t n_desc; uint64_t n_value; } mfnl;
typedef struct { uint32_t cmd, cmdsize; } mflc;
typedef struct { uint32_t cmd, cmdsize; char segname[16]; uint64_t vmaddr, vmsize, fileoff, filesize; uint32_t maxprot, initprot, nsects, flags; } mfseg;
typedef struct { char sectname[16], segname[16]; uint64_t addr, size; uint32_t offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3; } mfsect;
typedef struct { mflc lc; uint32_t symoff, nsyms, stroff, strsize; } mfsymcmd;
typedef struct { mflc lc; uint32_t ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym, nundefsym, tocoff, ntoc, modtaboff, nmodtab, extrefsymoff, nextrefsyms, indirectsymoff, nindirectsyms, extreloff, nextrel, locreloff, nlocrel; } mfdysym;

#define MF_IND_ABS  0x40000000u
#define MF_IND_LOC  0x80000000u

typedef struct { const char *name; void *repl; void **orig; } MFRebindEnt;

static void mfFishhookApply(MFRebindEnt *ents, int cnt) {
    int bound = 0, sections = 0;
    uint32_t ic = _dyld_image_count();
    for (uint32_t img = 0; img < ic; img++) {
        @autoreleasepool {
            const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(img);
            if (!mh || mh->magic != MH_MAGIC_64) continue;
            intptr_t slide = _dyld_get_image_vmaddr_slide(img);
            const mfseg *linkedit = NULL;
            const mfsymcmd *sc = NULL;
            const mfdysym *dsc = NULL;
            const uint8_t *p = (const uint8_t *)(mh + 1);
            const uint8_t *end = p + mh->sizeofcmds;
            while (p + sizeof(mflc) <= end) {
                const mflc *lc = (const mflc *)p;
                if (lc->cmdsize < sizeof(mflc) || p + lc->cmdsize > end) break;
                if (lc->cmd == LC_SEGMENT_64 && !strcmp(((const mfseg *)p)->segname, "__LINKEDIT")) linkedit = (const mfseg *)p;
                else if (lc->cmd == LC_SYMTAB) sc = (const mfsymcmd *)p;
                else if (lc->cmd == LC_DYSYMTAB) dsc = (const mfdysym *)p;
                p += lc->cmdsize;
            }
            if (!linkedit || !sc || !dsc || !dsc->indirectsymoff || !sc->nsyms) continue;
            uintptr_t lebase = (uintptr_t)linkedit->vmaddr - linkedit->fileoff + slide;
            const mfnl *syms = (const mfnl *)(lebase + sc->symoff);
            const char *strs = (const char *)(lebase + sc->stroff);
            const uint32_t *inds = (const uint32_t *)(lebase + dsc->indirectsymoff);

            // 第二遍：__DATA / __DATA_CONST 的符号指针段
            p = (const uint8_t *)(mh + 1);
            while (p + sizeof(mflc) <= end) {
                const mflc *lc = (const mflc *)p;
                if (lc->cmdsize < sizeof(mflc) || p + lc->cmdsize > end) break;
                if (lc->cmd == LC_SEGMENT_64) {
                    const mfseg *sg = (const mfseg *)p;
                    if (!strcmp(sg->segname, "__DATA") || !strcmp(sg->segname, "__DATA_CONST")) {
                        BOOL unprotected = NO;
                        const mfsect *sec = (const mfsect *)(sg + 1);
                        for (uint32_t s2 = 0; s2 < sg->nsects; s2++) {
                            const mfsect *sct = &sec[s2];
                            uint32_t type = sct->flags & 0x7;
                            if (type != S_NON_LAZY_SYMBOL_POINTERS && type != S_LAZY_SYMBOL_POINTERS) continue;
                            if (!unprotected && sg->segname[6] == '_' /* __DATA_CONST */) {
                                unprotected = YES;
                                mach_vm_protect(mach_task_self(), (mach_vm_address_t)(sct->addr + slide), sct->size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                            }
                            const uint32_t *ind = inds + sct->reserved1;
                            void **slot = (void **)(sct->addr + slide);
                            sections++;
                            for (uint32_t j = 0; j < sct->size / sizeof(void *); j++) {
                                uint32_t si = ind[j];
                                if (si == MF_IND_ABS || si == MF_IND_LOC || si >= sc->nsyms) continue;
                                const char *nm = strs + syms[si].n_strx;
                                if (nm[0] == '_') nm++; // Mach-O C 符号带前导下划线——v1.9.4 修复 0 命中根因
                                for (int e = 0; e < cnt; e++) {
                                    if (strcmp(nm, ents[e].name)) continue;
                                    if (*ents[e].orig == NULL) *ents[e].orig = slot[j]; // 首个命中记录原函数
                                    slot[j] = ents[e].repl;                             // 所有命中槽位都换
                                    bound++;
                                    break;
                                }
                            }
                        }
                    }
                }
                p += lc->cmdsize;
            }
        }
    }
    mfLog(@"[crypto] GOT rebind: %d slots across %d ptr-sections", bound, sections);
    if (!bound) mfLog(@"[crypto] ⚠️ 未命中任何槽位——检查符号名/段类型");
}

void mfInstallCryptoHooks(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_streamMap = [NSMutableDictionary new];
        MFRebindEnt ents[] = {
            {"CCCrypt",               (void *)my_CCCrypt,                  (void **)&o_CCCrypt},
            {"CCCryptorCreate",       (void *)my_CCCryptorCreate,          (void **)&o_CCCryptorCreate},
            {"CCCryptorCreateWithMode",(void *)my_CCCryptorCreateWithMode, (void **)&o_CCCryptorCreateWithMode},
            {"CCCryptorUpdate",       (void *)my_CCCryptorUpdate,          (void **)&o_CCCryptorUpdate},
            {"CCCryptorFinal",        (void *)my_CCCryptorFinal,           (void **)&o_CCCryptorFinal},
            {"CCHmac",                (void *)my_CCHmac,                   (void **)&o_CCHmac},
            {"EVP_EncryptUpdate",     (void *)my_EVP_EncryptUpdate,        (void **)&o_EVP_EncryptUpdate},
            {"EVP_DecryptUpdate",     (void *)my_EVP_DecryptUpdate,        (void **)&o_EVP_DecryptUpdate},
            {"EVP_CipherUpdate",      (void *)my_EVP_CipherUpdate,         (void **)&o_EVP_CipherUpdate},
            {"HMAC",                  (void *)my_OSSLHMAC,                 (void **)&o_OSSLHMAC},
        };
        o_CCCrypt = o_CCCryptorCreate = o_CCCryptorCreateWithMode = NULL;
        o_CCCryptorUpdate = o_CCCryptorFinal = o_CCHmac = NULL;
        o_EVP_EncryptUpdate = o_EVP_DecryptUpdate = o_EVP_CipherUpdate = o_OSSLHMAC = NULL;
        mfFishhookApply(ents, 10);
        mfLog(@"[crypto] resolved: CC=%d%d%d%d%d%d EVP=%d%d%d%d",
              o_CCCrypt!=NULL, o_CCCryptorCreate!=NULL, o_CCCryptorCreateWithMode!=NULL,
              o_CCCryptorUpdate!=NULL, o_CCCryptorFinal!=NULL, o_CCHmac!=NULL,
              o_EVP_EncryptUpdate!=NULL, o_EVP_DecryptUpdate!=NULL,
              o_EVP_CipherUpdate!=NULL, o_OSSLHMAC!=NULL);
        g_cryptoHookInstalled = YES;
    });
}

#pragma mark - 页面

@interface MFCryptoCapList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *recs;
@end
@implementation MFCryptoCapList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return (NSInteger)self.recs.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *id_ = @"mfcaprow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:id_];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:id_];
    MFCryptoRecord *r = self.recs[ip.row];
    c.textLabel.text = [NSString stringWithFormat:@"%@ · %@", r.dir, r.kind];
    c.textLabel.font = [UIFont systemFontOfSize:12];
    c.textLabel.textColor = [UIColor labelColor];
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"HH:mm:ss";
    c.detailTextLabel.text = [NSString stringWithFormat:@"%@ | key %@ | %luB", [df stringFromDate:r.ts], r.keyHex ?: @"-", (unsigned long)(r.output.length ?: r.input.length)];
    c.detailTextLabel.font = [UIFont systemFontOfSize:10];
    c.detailTextLabel.textColor = [UIColor tertiaryLabelColor];
    c.backgroundColor = UIColor.clearColor;
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    MFCryptoRecord *r = self.recs[ip.row];
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"类型: %@\n方向: %@\n时间: %@\n\n【Key】\n%@\n\n【IV】\n%@\n",
        r.kind, r.dir, r.ts, r.keyHex ?: @"-", r.ivHex ?: @"-"];
    [s appendFormat:@"\n【输入 hex】(%luB)\n%@\n", (unsigned long)r.input.length, mfHex(r.input, 512)];
    NSString *inU = mfTryUtf8(r.input);
    if (inU) [s appendFormat:@"\n【输入 UTF8?】\n%@\n", inU];
    [s appendFormat:@"\n【输出 hex】(%luB)\n%@\n", (unsigned long)r.output.length, mfHex(r.output, 512)];
    NSString *outU = mfTryUtf8(r.output);
    if (outU) [s appendFormat:@"\n【输出 UTF8?】\n%@\n", outU];
    mfShowTextReportPage(r.kind, s, @"CryptoCapture");
}
@end

// Ctrl wrapper 调用
void mfCryptoCapSwitchChanged(UISwitch *sw) {
    mfSetBoolPref(@"mfCryptoCapture", sw.on);
    if (sw.on) mfInstallCryptoHooks();
    mfToast(sw.on ? @"🔓 解密捕获已开启" : @"🔒 解密捕获已关闭");
}

void mfCryptoClearTapped(void) {
    @synchronized (g_cryptoRecs) { [g_cryptoRecs removeAllObjects]; }
    mfToast(@"🗑️ 记录已清空");
}

void mfShowCryptoCapturePage(void) {
    UIView *page = mfMakePage(@"🔓 解密捕获", YES);

    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 90, 24)];
    lb.text = @"⏺ 实时捕获 CCCrypt/HMAC";
    lb.font = [UIFont boldSystemFontOfSize:13];
    lb.textColor = [UIColor labelColor];
    [page addSubview:lb];
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(g_mfCardW - 68, 44, 51, 31)];
    sw.on = mfCryptoEnabledState();
    objc_setAssociatedObject(sw, "on", @(1), OBJC_ASSOCIATION_RETAIN);
    [page addSubview:sw];

    UIButton *clrBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    clrBtn.frame = CGRectMake(16, 82, g_mfCardW - 32, 34);
    clrBtn.backgroundColor = [UIColor secondarySystemBackgroundColor];
    clrBtn.layer.cornerRadius = 8;
    [clrBtn setTitle:@"清空记录" forState:UIControlStateNormal];
    clrBtn.tintColor = [UIColor labelColor];
    objc_setAssociatedObject(clrBtn, "sw", sw, OBJC_ASSOCIATION_RETAIN);
    [page addSubview:clrBtn];

    UITableView *tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 122, g_mfCardW, g_mfCardH - 122) style:UITableViewStylePlain];
    tv.backgroundColor = UIColor.clearColor;
    tv.separatorStyle = UITableViewCellSeparatorStyleNone;
    tv.rowHeight = 52;
    MFCryptoCapList *ds = [MFCryptoCapList new];
    ds.recs = mfCryptoRecordsSnapshot();
    tv.dataSource = ds;
    tv.delegate = ds;
    objc_setAssociatedObject(page, "capDS", ds, OBJC_ASSOCIATION_RETAIN);

    // 定时刷新列表 + 开关状态同步
    __block NSTimer *timer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *t) {
        if (!g_mfPanelOverlay) { [t invalidate]; return; }
        sw.on = mfCryptoEnabledState();
        NSArray *snap = mfCryptoRecordsSnapshot();
        if (![snap isEqualToArray:ds.recs]) {
            ds.recs = snap;
            [tv reloadData];
        }
    }];
    objc_setAssociatedObject(page, "capTimer", timer, OBJC_ASSOCIATION_RETAIN);

    // 控件事件 → Ctrl wrapper（静态方法，MFPanel.m @implementation MFPanelCtrl）
    [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [clrBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoClearTapped") forControlEvents:UIControlEventTouchUpInside];

    // 首次打开即预装 hook（开关开着才生效）
    if (mfCryptoEnabledState()) mfInstallCryptoHooks();

    [page addSubview:tv];
    mfPushPage(page);
}
