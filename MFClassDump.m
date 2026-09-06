// MFClassDump.m — 运行时 class dump（v1.4.0 新增，数据分析板块）
// 思路来源：RuntimeClassDump.dylib 逆向（CD* 模型层），实现全部自研：
// objc runtime API 枚举 → 内存生成 .h → 内置 zip writer（zlib deflate）→ 分享
// 零第三方依赖，不落盘中间文件

#import "MFPanel.h"
#include <zlib.h>
#include <time.h>
#include <ctype.h>

// ====== 类型编码 → C 类型（精简版 CDTypeParser） ======
static NSString *mfDecOne(const char *e, NSUInteger *ip) {
    NSUInteger i = *ip;
    if (i >= strlen(e)) return @"void";
    char c = e[i];
    switch (c) {
        case 'v': *ip=i+1; return @"void";
        case 'B': *ip=i+1; return @"_Bool";
        case 'c': *ip=i+1; return @"char";
        case 'C': *ip=i+1; return @"unsigned char";
        case 's': *ip=i+1; return @"short";
        case 'S': *ip=i+1; return @"unsigned short";
        case 'i': *ip=i+1; return @"int";
        case 'I': *ip=i+1; return @"unsigned int";
        case 'l': *ip=i+1; return @"long";
        case 'L': *ip=i+1; return @"unsigned long";
        case 'q': *ip=i+1; return @"long long";
        case 'Q': *ip=i+1; return @"unsigned long long";
        case 'f': *ip=i+1; return @"float";
        case 'd': *ip=i+1; return @"double";
        case '@': {
            if (e[i+1] == '"') {
                const char *q = strchr(e+i+2, '"');
                NSString *cls = q ? [NSString stringWithFormat:@"%.*s *", (int)(q-(e+i+2)), e+i+2]
                                  : @"id";
                *ip = q ? (q - e + 1) : i+2;
                return cls;
            }
            if (e[i+1] == '?') { *ip=i+2; return @"void (^)(void)"; } // block 简化
            *ip=i+1; return @"id";
        }
        case '#': *ip=i+1; return @"Class";
        case ':': *ip=i+1; return @"SEL";
        case '^': {
            *ip=i+1;
            NSString *inner = mfDecOne(e, ip);
            return [NSString stringWithFormat:@"%@ *", inner];
        }
        case '[': { // [nT]
            NSUInteger j=i+1;
            while (isdigit((unsigned char)e[j])) j++;
            NSString *t = mfDecOne(e, &j); j++; // 跳 ]
            *ip=j;
            return [NSString stringWithFormat:@"%@[%@]", t, @""];
        }
        case '{': { // {name=...}
            NSUInteger j = i+1;
            const char *eq = strchr(e+j, '=');
            const char *rb = strchr(e+j, '}');
            if (!rb) { *ip=strlen(e); return @"struct"; }
            NSUInteger nlen = eq && eq < rb ? (NSUInteger)(eq-(e+j)) : (NSUInteger)(rb-(e+j));
            NSString *t = [NSString stringWithFormat:@"struct %.*s", (int)nlen, e+j];
            j = rb - e + 1;
            *ip=j; return t;
        }
        case '(': { // (name=...)
            const char *rb = strchr(e+i+1, ')');
            NSUInteger nlen = rb ? (NSUInteger)(rb-(e+i+1)) : 0;
            *ip = rb ? rb-e+1 : strlen(e);
            return [NSString stringWithFormat:@"union %.*s", (int)nlen, e+i+1];
        }
        case 'j': *ip=i+1; return @"_Complex";
        case 'b': *ip=i+1; return @"bitfield";
        default:  *ip=i+1; return nil; // 数字(对齐)/?/未知 → 跳过
    }
}

static NSString *mfDecodeType(const char *enc) {
    if (!enc || !*enc) return @"void";
    NSUInteger i = 0;
    NSString *t = mfDecOne(enc, &i);
    return t ?: @"void";
}

// ====== 方法渲染：- (ret)sela:(arg)a1 b:(arg)a2; ======
static NSString *mfRenderMethod(Method m, BOOL isCls) {
    // 老版 SDK 把 method_getReturnType 声明为 (m,dst,len) 遗留变体，统一用 copy 系
    char *retp = method_copyReturnType(m);
    NSMutableString *sig = [NSMutableString string];
    [sig appendFormat:@"%c (%@)", isCls ? '+' : '-', mfDecodeType(retp)];
    if (retp) free(retp);
    SEL sel = method_getName(m);
    NSArray *parts = [NSStringFromSelector(sel) componentsSeparatedByString:@":"];
    int ai = 0;
    for (NSUInteger p = 0; p < parts.count; p++) {
        if (p == 0) [sig appendFormat:@"%@", parts[0]];
        else {
            const char *ae = method_copyArgumentType(m, 2 + ai);
            NSString *at = mfDecodeType(ae); free(ae); ai++;
            [sig appendFormat:@":(%@)a%d %@", at, ai, parts[p]];
        }
    }
    [sig appendString:@";"];
    return sig;
}

// ====== 单类头文件生成 ======
static NSString *mfHeaderForClass(Class cls) {
    const char *nm = class_getName(cls);
    Class sup = class_getSuperclass(cls);
    NSMutableString *h = [NSMutableString string];

    // 协议
    NSMutableArray *protos = [NSMutableArray array];
    unsigned pc = 0;
    Protocol * __unsafe_unretained *pl = class_copyProtocolList(cls, &pc);
    for (unsigned i = 0; i < pc; i++) [protos addObject:@(protocol_getName(pl[i]))];
    free(pl);

    [h appendFormat:@"@interface %s", nm];
    if (sup) [h appendFormat:@" : %s", class_getName(sup)];
    if (protos.count) [h appendFormat:@" <%@>", [protos componentsJoinedByString:@", "]];
    [h appendString:@"\n{\n"];

    unsigned ic = 0;
    Ivar *iv = class_copyIvarList(cls, &ic);
    for (unsigned i = 0; i < ic; i++) {
        const char *tn = ivar_getTypeEncoding(iv[i]);
        ptrdiff_t off = ivar_getOffset(iv[i]);
        [h appendFormat:@"    %@ _%s; // +%td\n",
            mfDecodeType(tn), ivar_getName(iv[i]) ?: "?", off];
    }
    free(iv);
    [h appendString:@"}\n"];

    // 实例方法
    unsigned mc = 0;
    Method *ml = class_copyMethodList(cls, &mc);
    for (unsigned i = 0; i < mc; i++) [h appendFormat:@"%@\n", mfRenderMethod(ml[i], NO)];
    // 类方法（元类）
    unsigned cmc = 0;
    Method *cml = class_copyMethodList(object_getClass(cls), &cmc);
    for (unsigned i = 0; i < cmc; i++) [h appendFormat:@"%@\n", mfRenderMethod(cml[i], YES)];
    free(ml); free(cml);

    // 属性
    unsigned prc = 0;
    objc_property_t *pr = class_copyPropertyList(cls, &prc);
    for (unsigned i = 0; i < prc; i++) {
        const char *attrs = property_getAttributes(pr[i]);
        NSString *type = @"id", *mods = @"";
        if (attrs && attrs[0]=='T') {
            const char *comma = strchr(attrs+1, ',');
            type = comma ? [NSString stringWithFormat:@"%.*s", (int)(comma-attrs-1), attrs+1] : @(attrs+1);
            type = type.length ? mfDecodeType(type.UTF8String) : @"id";
            NSMutableArray *kw = [NSMutableArray array];
            for (const char *p = comma ? comma+1 : attrs+strlen(attrs); *p; ) {
                switch (*p) {
                    case 'R': [kw addObject:@"readonly"]; break;
                    case 'C': [kw addObject:@"copy"]; break;
                    case '&': [kw addObject:@"strong"]; break;
                    case 'N': [kw addObject:@"nonatomic"]; break;
                    case 'W': [kw addObject:@"weak"]; break;
                }
                const char *nx = strchr(p, ',');
                if (!nx) break; p = nx+1;
            }
            mods = kw.count ? [kw componentsJoinedByString:@", "] : @"nonatomic";
        }
        [h appendFormat:@"@property(%@) %@ %s;\n", mods, type, property_getName(pr[i])];
    }
    free(pr);

    [h appendString:@"@end\n"];
    return h;
}

// ====== 最小 ZIP writer（deflate via zlib）======
static void mfPut16(NSMutableData *d, uint16_t v) { [d appendBytes:&v length:2]; }
static void mfPut32(NSMutableData *d, uint32_t v) { [d appendBytes:&v length:4]; }
static void mfPut64(NSMutableData *d, uint64_t v) { [d appendBytes:&v length:8]; }
static uint16_t mfLE16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t mfLE32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

// 中央目录记录：必须用 ObjC 对象持有 name（NSValue+裸结构体会 UAF，v2 闪退根因）
@interface MFCDRec : NSObject
@property (copy) NSString *name;
@property (assign) uint32_t crc, csize, usize, offset;
@property (assign) uint16_t method;
@end
@implementation MFCDRec @end

static void mfZipTime(uint16_t *t, uint16_t *dt) {
    time_t now = time(NULL);
    struct tm tmv; localtime_r(&now, &tmv);
    *t  = (uint16_t)((tmv.tm_hour << 11) | (tmv.tm_min << 5) | (tmv.tm_sec >> 1));
    *dt = (uint16_t)(((tmv.tm_year + 1900 - 1980) << 9) | ((tmv.tm_mon + 1) << 5) | tmv.tm_mday);
}

// RAW deflate（ZIP 要求裸流；compress2 的 zlib 包装会导致解压失败）
static BOOL mfRawDeflate(const uint8_t *src, uLong srcLen, uint8_t *dst, uLongf *dstLen) {
    z_stream zs; memset(&zs, 0, sizeof(zs));
    if (deflateInit2(&zs, Z_BEST_SPEED, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) return NO;
    zs.next_in = (Bytef *)src; zs.avail_in = (uInt)srcLen;
    zs.next_out = dst; zs.avail_out = (uInt)*dstLen;
    int rc = deflate(&zs, Z_FINISH);
    *dstLen = zs.total_out;
    deflateEnd(&zs);
    return rc == Z_STREAM_END;
}

// 流式写单条目到文件句柄，CD 记录进数组（最后统一追加）
static BOOL mfZipAddStream(NSFileHandle *fh, NSMutableArray *cds, NSString *name, NSData *data,
                           NSMutableData *scratch) {
    @try {
        uint16_t mtime, mdate; mfZipTime(&mtime, &mdate);
        uint32_t crc = (uint32_t)crc32(0, data.bytes, (uInt)data.length);

        // 裸 deflate 到复用 scratch 缓冲
        uLongf bound = compressBound(data.length);
        if (scratch.length < bound) [scratch setLength:bound];
        uLongf csz = scratch.length;
        int ok = mfRawDeflate(data.bytes, data.length, scratch.mutableBytes, &csz);
        BOOL stored = (!ok || csz >= data.length);
        uint16_t method = stored ? 0 : 8;
        uint32_t finalSize = stored ? (uint32_t)data.length : (uint32_t)csz;

        uint32_t off = (uint32_t)fh.offsetInFile;
        NSMutableData *lh = [NSMutableData dataWithCapacity:30 + name.length];
        mfPut32(lh, 0x04034b50); mfPut16(lh, 20); mfPut16(lh, 0x0800);
        mfPut16(lh, method); mfPut16(lh, mtime); mfPut16(lh, mdate);
        mfPut32(lh, crc);
        mfPut32(lh, finalSize);
        mfPut32(lh, (uint32_t)data.length);
        NSData *nb = [name dataUsingEncoding:NSUTF8StringEncoding];
        mfPut16(lh, (uint16_t)nb.length); mfPut16(lh, 0);
        [lh appendData:nb];
        [fh writeData:lh];
        [fh writeData:(stored ? data : [NSData dataWithBytesNoCopy:scratch.mutableBytes length:csz freeWhenDone:NO])];

        MFCDRec *rec = [MFCDRec new];
        rec.name = name; rec.crc = crc; rec.csize = finalSize;
        rec.usize = (uint32_t)data.length; rec.offset = off; rec.method = method;
        [cds addObject:rec];
        return YES;
    } @catch (NSException *ex) {
        mfLog(@"CLASSDUMP zip entry failed: %@", ex.reason);
        return NO;
    }
}

static BOOL mfZipFinishStream(NSFileHandle *fh, NSMutableArray *cds) {
    @try {
        uint32_t cdOff = (uint32_t)fh.offsetInFile;
        NSMutableData *cd = [NSMutableData data];
        for (MFCDRec *e in cds) {
            uint16_t mtime, mdate; mfZipTime(&mtime, &mdate);
            mfPut32(cd, 0x02014b50); mfPut16(cd, 20); mfPut16(cd, 20);
            mfPut16(cd, 0x0800); mfPut16(cd, e.method);
            mfPut16(cd, mtime); mfPut16(cd, mdate);
            mfPut32(cd, e.crc); mfPut32(cd, e.csize); mfPut32(cd, e.usize);
            NSData *nb = [e.name dataUsingEncoding:NSUTF8StringEncoding];
            mfPut16(cd, (uint16_t)nb.length);
            mfPut16(cd, 0); mfPut16(cd, 0); mfPut16(cd, 0); mfPut16(cd, 0);
            mfPut32(cd, 0); mfPut32(cd, e.offset);
            [cd appendData:nb];
        }
        [fh writeData:cd];
        uint32_t cdSize = (uint32_t)cd.length;
        // ZIP64：条目数超 uint16 时必须补 ZIP64 EOCD，否则严格工具只见 65535 截断后的残缺列表
        BOOL need64 = cds.count > 0xFFFF || cdOff > 0xFFFFFFFFULL || cdSize > 0xFFFFFFFFULL;
        if (need64) {
            uint64_t z64Off = fh.offsetInFile;
            NSMutableData *z = [NSMutableData dataWithCapacity:56];
            mfPut32(z, 0x06064b50); mfPut64(z, 44);
            mfPut16(z, 45); mfPut16(z, 45); mfPut32(z, 0); mfPut32(z, 0);
            mfPut64(z, cds.count); mfPut64(z, cds.count);
            mfPut64(z, cdSize); mfPut64(z, cdOff);
            [fh writeData:z];
            NSMutableData *loc = [NSMutableData dataWithCapacity:20];
            mfPut32(loc, 0x07064b50); mfPut32(loc, 0);
            mfPut64(loc, z64Off); mfPut32(loc, 1);
            [fh writeData:loc];
        }
        NSMutableData *eo = [NSMutableData dataWithCapacity:22];
        mfPut32(eo, 0x06054b50); mfPut16(eo, 0); mfPut16(eo, 0);
        uint16_t eCnt = need64 ? 0xFFFF : (uint16_t)cds.count;
        mfPut16(eo, eCnt); mfPut16(eo, eCnt);
        mfPut32(eo, cdSize); mfPut32(eo, cdOff); mfPut16(eo, 0);
        [fh writeData:eo];
        return YES;
    } @catch (NSException *ex) {
        mfLog(@"CLASSDUMP zip finish failed: %@", ex.reason);
        return NO;
    }
}

// ====== Swift 类型扫描（__swift5_types → 伪接口）======
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>

// 相对指针解析（swift metadata 全是 i32 自相对），带镜像范围校验
static uintptr_t mfRelPtr(uintptr_t slotAddr, int32_t off, uintptr_t lo, uintptr_t hi) {
    if (off == 0) return 0;
    uintptr_t t = slotAddr + (uintptr_t)(int64_t)off;
    return (t >= lo && t < hi) ? t : 0;
}
// 读地址前先验证「要读的长度」落在镜像范围内——v1.9.1 崩溃修复：
// 只验目标地址不验读取长度，desc/fd 靠近段尾时 int32/NUL 扫描跨未映射页直接 SIGBUS
static BOOL mfRangeOK(uintptr_t addr, uintptr_t len, uintptr_t lo, uintptr_t hi) {
    return addr >= lo && len > 0 && addr <= hi && len <= hi - addr;
}
static const char *mfSafeStr(uintptr_t addr, uintptr_t lo, uintptr_t hi) {
    if (!mfRangeOK(addr, 1, lo, hi)) return NULL;
    const char *s = (const char *)addr;
    // 粗略可读性校验
    if (*s && !(*s >= 32 && *s < 127) && (unsigned char)*s < 0xC0) return NULL;
    // NUL 必须在 256 字节内且不出镜像边界，否则视为坏串
    uintptr_t cap = MIN((uintptr_t)256, hi - addr);
    for (uintptr_t i = 0; i < cap; i++) if (s[i] == '\0') return s;
    return NULL;
}

static NSString *mfSwiftKindName(uint8_t kind) {
    switch (kind) {
        case 16: return @"class";
        case 17: return @"struct";
        case 18: return @"enum";
        default: return nil;
    }
}

// 遍历单镜像 __swift5_types，输出伪接口文本
static NSString *mfSwiftDumpImage(const struct mach_header *mh, intptr_t slide, NSString **outModuleCount) {
    unsigned long sz = 0;
    // getsectiondata 内部处理 slide，返回的是已重定位地址
    const uint8_t *types = getsectiondata(mh, "__TEXT", "__swift5_types", &sz);
    if (!types || sz < 4) return nil;
    uintptr_t lo = (uintptr_t)mh, hi = lo; // 范围用所有段聚合
    {
        uintptr_t minA = ~0ull, maxA = 0;
        const struct mach_header_64 *h64 = (const struct mach_header_64 *)mh;
        const uint8_t *p = (const uint8_t *)(h64 + 1);
        // v1.9.1 崩溃修复：load commands 遍历加边界 + cmdsize 合法性校验，
        // 否则畸形镜像会让 p 跑飞到未映射页（SIGSEGV，@try 接不住）
        const uint8_t *cmdEnd = (const uint8_t *)mh + sizeof(struct mach_header_64) + h64->sizeofcmds;
        for (uint32_t i = 0; i < h64->ncmds; i++) {
            if (p + sizeof(struct load_command) > cmdEnd) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize < sizeof(struct load_command) || p + lc->cmdsize > cmdEnd) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
                // v1.9.2 关键修复：排除 __PAGEZERO（vmaddr=0, vmsize=4GB 未映射保留区）
                // 把它算进聚合会把 lo 拉到 ~0，范围窗口失效，坏指针全数过检后踩未映射页
                if (sg->vmaddr == 0 || sg->vmsize == 0) { p += lc->cmdsize; continue; }
                uintptr_t a = (uintptr_t)sg->vmaddr + slide, b = a + sg->vmsize;
                if (a < minA) minA = a;
                if (b > maxA) maxA = b;
            }
            p += lc->cmdsize;
        }
        if (!maxA) return nil;
        lo = minA; hi = maxA;
    }

    NSMutableString *out = [NSMutableString string];
    __block NSUInteger count = 0;
    const int32_t *rels = (const int32_t *)types;
    size_t n = sz / 4;
    for (size_t i = 0; i < n; i++) {
        uintptr_t descAddr = mfRelPtr((uintptr_t)&rels[i], rels[i], lo, hi);
        if (!descAddr) continue;
        // v1.9.1：读 desc[0..4] 前验证 20 字节在镜像内
        if (!mfRangeOK(descAddr, 20, lo, hi)) continue;
        const int32_t *desc = (const int32_t *)descAddr;
        uint32_t flags = (uint32_t)desc[0];
        uint8_t kind = flags & 0x1F;
        NSString *kindName = mfSwiftKindName(kind);
        if (!kindName) continue;
        const char *tname = mfSafeStr(mfRelPtr(descAddr + 8, desc[2], lo, hi), lo, hi);
        if (!tname || !*tname) continue;

        // 模块名：parent 链上溯
        NSString *module = @"Unknown";
        {
            uintptr_t pa = mfRelPtr(descAddr + 4, desc[1], lo, hi);
            int depth = 0;
            while (pa && depth++ < 8) {
                if (!mfRangeOK(pa, 12, lo, hi)) break; // 读 pd[0..2] 前验长
                const int32_t *pd = (const int32_t *)pa;
                uint8_t pk = (uint32_t)pd[0] & 0x1F;
                if (pk != 0 && pk != 1) break; // 只沿 Module/Extension 上溯
                if (pk == 0) { // Module
                    const char *mn = mfSafeStr(mfRelPtr(pa + 8, pd[2], lo, hi), lo, hi);
                    if (mn) module = @(mn);
                    break;
                }
                pa = mfRelPtr(pa + 4, pd[1], lo, hi);
            }
        }
        (void)module; // v1: 按镜像归档即可，模块名留作后续分组

        [out appendFormat:@"%@ %s {\n", kindName, tname];
        // 字段描述符 @+16
        uintptr_t fd = mfRelPtr(descAddr + 16, desc[4], lo, hi);
        if (fd && mfRangeOK(fd, 16, lo, hi)) { // 读 frecSize/nf 前验长
            uint16_t frecSize = *(const uint16_t *)(fd + 10);
            uint32_t nf = *(const uint32_t *)(fd + 12);
            if (nf > 4096) nf = 4096; // 防御
            for (uint32_t f = 0; f < nf && frecSize > 0; f++) { // frecSize==0 防死循环
                uintptr_t fr = fd + 16 + (uintptr_t)f * frecSize;
                if (!mfRangeOK(fr, 12, lo, hi)) break;
                const int32_t *fri = (const int32_t *)fr;
                const char *fname = mfSafeStr(mfRelPtr(fr + 8, fri[2], lo, hi), lo, hi);
                if (!fname) fname = "?";
                const char *mty = mfSafeStr(mfRelPtr(fr + 4, fri[1], lo, hi), lo, hi);
                NSString *ty = mty ? @(mty) : @"?";
                [out appendFormat:@"    %@ %s: %@\n",
                    (kind == 18 ? @"case" : @"var"), fname, ty];
            }
        }
        [out appendString:@"}\n\n"];
        count++;
    }
    if (outModuleCount) *outModuleCount = @(count);
    return count ? out : nil;
}

// 扫全部镜像，产出 swift/<Image>.swift 条目
static void mfDumpAllSwift(NSFileHandle *fh, NSMutableArray *cds, NSMutableData *scratch,
                           NSMutableArray<NSString *> *modules) {
    uint32_t ic = _dyld_image_count();
    for (uint32_t i = 0; i < ic; i++) {
        @autoreleasepool {
            const struct mach_header *mh = _dyld_get_image_header(i);
            if (!mh) continue;
            const char *path = _dyld_get_image_name(i);
            NSString *imgName = path ? [@(path) lastPathComponent] : [NSString stringWithFormat:@"img%u", i];
            NSString *cnt = nil;
            NSString *body = mfSwiftDumpImage(mh, (intptr_t)_dyld_get_image_vmaddr_slide(i), &cnt);
            if (!body) continue;
            NSString *header = [NSString stringWithFormat:@"// Swift types in %@ (%@ types)\n// 由 __swift5_types 元数据还原，字段类型为 mangled 原始串\n\n", imgName, cnt ?: @"0"];
            NSString *full = [header stringByAppendingString:body];
            [modules addObject:[NSString stringWithFormat:@"%@ (%@)", imgName, cnt]];
            NSString *safeImg = [[imgName stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
                                  stringByReplacingOccurrencesOfString:@":" withString:@"_"];
            mfZipAddStream(fh, cds, [NSString stringWithFormat:@"swift/%@.swift", safeImg],
                           [full dataUsingEncoding:NSUTF8StringEncoding], scratch);
        }
    }
}

// ====== 主流程（流式落盘：内存峰值 = 单类头文件，防 jetsam） ======
void mfClassDumpStartAction(UIProgressView *pv, UILabel *lb, UIButton *btn, UIView *actionRow) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        unsigned total = 0;
        Class *classes = objc_copyClassList(&total);
        mfLog(@"CLASSDUMP start: %u classes", total);
        if (!total || !classes) {
            dispatch_async(dispatch_get_main_queue(), ^{ lb.text = @"⚠️ 无类可枚举"; btn.enabled = YES; });
            return;
        }
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0]
                            stringByAppendingPathComponent:@"classdump"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *app = [[[NSBundle mainBundle] bundleIdentifier] lastPathComponent] ?: @"App";
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"yyyyMMdd_HHmm";
        NSString *finalPath = [dir stringByAppendingFormat:@"/%@_Dump_%@.zip", app, [df stringFromDate:[NSDate date]]];
        NSString *tmpPath = [finalPath stringByAppendingString:@".building"];

        [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
        if (![[NSFileManager defaultManager] createFileAtPath:tmpPath contents:nil attributes:nil]) {
            mfLog(@"CLASSDUMP create file FAILED");
            dispatch_async(dispatch_get_main_queue(), ^{ lb.text = @"⚠️ 无法创建输出文件"; btn.enabled = YES; });
            free(classes); return;
        }
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:tmpPath];
        NSMutableData *scratch = [NSMutableData dataWithCapacity:1 << 16];
        NSMutableArray *cds = [NSMutableArray array];
        NSMutableSet *seen = [NSMutableSet set];
        unsigned done = 0;

        for (unsigned i = 0; i < total; i++) {
            @autoreleasepool {
                @try {
                    const char *nm = class_getName(classes[i]);
                    if (!nm || !*nm) continue;
                    NSString *name = @(nm);
                    if ([seen containsObject:name]) continue;
                    [seen addObject:name];
                    NSString *fname = [[name stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
                                        stringByAppendingString:@".h"];
                    NSString *body = mfHeaderForClass(classes[i]);
                    if (body) mfZipAddStream(fh, cds, fname, [body dataUsingEncoding:NSUTF8StringEncoding], scratch);
                } @catch (NSException *ex) {
                    mfLog(@"CLASSDUMP class %u failed: %@", i, ex.name);
                }
            }
            done++;
            if (done % 500 == 0 || done == total) {
                float frac = (float)done / total;
                unsigned d = done;
                dispatch_async(dispatch_get_main_queue(), ^{
                    pv.progress = frac;
                    lb.text = [NSString stringWithFormat:@"正在生成头文件... %.0f%% (%u/%u)", frac * 100, d, total];
                });
            }
        }
        free(classes);
        mfLog(@"CLASSDUMP generated %u headers, scanning Swift metadata", (unsigned)cds.count);

        dispatch_async(dispatch_get_main_queue(), ^{
            lb.text = @"正在扫描 Swift 类型...";
        });

        // Swift 元数据阶段
        NSMutableArray<NSString *> *swiftModules = [NSMutableArray array];
        @try {
            mfDumpAllSwift(fh, cds, scratch, swiftModules);
            mfLog(@"CLASSDUMP swift modules with types: %lu", (unsigned long)swiftModules.count);
        } @catch (NSException *ex) {
            mfLog(@"CLASSDUMP swift phase failed: %@", ex.reason);
        }

        mfLog(@"CLASSDUMP writing central dir (%u entries)", (unsigned)cds.count);
        // finish 标记 + 中央目录
        mfZipAddStream(fh, cds, @"finish.txt", [@"finish" dataUsingEncoding:NSUTF8StringEncoding], scratch);
        BOOL ok = mfZipFinishStream(fh, cds);
        [fh closeFile];

        if (!ok || cds.count < 2) {
            [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
            dispatch_async(dispatch_get_main_queue(), ^{ lb.text = @"⚠️ 压缩失败，详见日志"; btn.enabled = YES; });
            return;
        }
        // 原子落位：.building → 正式名
        [[NSFileManager defaultManager] removeItemAtPath:finalPath error:nil];
        NSError *mvErr = nil;
        [[NSFileManager defaultManager] moveItemAtPath:tmpPath toPath:finalPath error:&mvErr];
        if (mvErr) mfLog(@"CLASSDUMP move failed: %@", mvErr.localizedDescription);

        unsigned cnt = (unsigned)cds.count;
        NSDictionary *szAt = [[NSFileManager defaultManager] attributesOfItemAtPath:finalPath error:nil];
        mfLog(@"CLASSDUMP done: %@ size=%@", finalPath, szAt[NSFileSize]);

        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *sw = swiftModules.count ? [NSString stringWithFormat:@"\nSwift 模块：%lu 个", (unsigned long)swiftModules.count] : @"";
            NSString *szStr = szAt[NSFileSize] ? [NSString stringWithFormat:@"%.1f MB", [szAt[NSFileSize] doubleValue] / 1048576.0] : @"?";
            lb.text = [NSString stringWithFormat:@"✅ 完成：%u 条目（%@）%@\n↓ 导出可存到 下载/任意位置", cnt, szStr, sw];
            btn.enabled = YES;
            // path 挂到导出 + 浏览两个按钮
            NSArray *trio = objc_getAssociatedObject(btn, "trio");
            UIButton *exBtn = trio.count > 2 ? trio[2] : nil;
            UIButton *brBtn = trio.count > 3 ? trio[3] : nil;
            if (exBtn) { objc_setAssociatedObject(exBtn, "path", finalPath, OBJC_ASSOCIATION_RETAIN_NONATOMIC); exBtn.hidden = NO; }
            if (brBtn) { objc_setAssociatedObject(brBtn, "path", finalPath, OBJC_ASSOCIATION_RETAIN_NONATOMIC); brBtn.hidden = NO; }
        });
    });
}

// ====== 页面入口 ======
void mfShowClassDumpPage(void) {
    UIView *page = mfMakePage(@"ClassDump", YES);
    CGFloat gw = g_mfCardW - 32;

    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"未知";
    UILabel *info = [[UILabel alloc] initWithFrame:CGRectMake(16, 48, gw, 40)];
    info.numberOfLines = 2;
    info.font = [UIFont systemFontOfSize:12];
    info.textColor = [UIColor secondaryLabelColor];
    info.text = [NSString stringWithFormat:@"%@\n%u 个 ObjC 类待导出（含 Swift 类型）", bid, objc_getClassList(NULL, 0)];
    [page addSubview:info];

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(16, 96, gw, 44);
    btn.backgroundColor = [UIColor systemBlueColor];
    btn.layer.cornerRadius = 10;
    btn.tintColor = UIColor.whiteColor;
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [btn setTitle:@"开始 Dump 并压缩" forState:UIControlStateNormal];
    [page addSubview:btn];

    UIProgressView *pv = [[UIProgressView alloc] initWithProgressViewStyle:UIProgressViewStyleDefault];
    pv.frame = CGRectMake(16, 156, gw, 8);
    [page addSubview:pv];

    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(16, 172, gw, 60)];
    lb.font = [UIFont systemFontOfSize:12];
    lb.textColor = [UIColor secondaryLabelColor];
    lb.numberOfLines = 3;
    lb.text = @"ObjC 全类 + Swift 类型 → zip\n输出 Documents/classdump，可保存到文件App";
    [page addSubview:lb];

    // 完成后的内联导出按钮（分享面板自带"存储到文件"）
    UIButton *exportBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    exportBtn.frame = CGRectMake(16, 240, gw, 44);
    exportBtn.backgroundColor = [UIColor systemGreenColor];
    exportBtn.layer.cornerRadius = 10;
    exportBtn.tintColor = UIColor.whiteColor;
    exportBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    exportBtn.hidden = YES;
    [exportBtn setTitle:@"📤 导出 zip（可存到文件App）" forState:UIControlStateNormal];
    [exportBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClassDumpExport:") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:exportBtn];

    UIButton *browseBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    browseBtn.frame = CGRectMake(16, 292, gw, 44);
    browseBtn.backgroundColor = [UIColor systemIndigoColor];
    browseBtn.layer.cornerRadius = 10;
    browseBtn.tintColor = UIColor.whiteColor;
    browseBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    browseBtn.hidden = YES;
    [browseBtn setTitle:@"📖 浏览头文件" forState:UIControlStateNormal];
    [browseBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCDBrowserOpen:") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:browseBtn];

    // 历史记录（v1.9.3：zip 持久化管理，免重复 dump 积压垃圾）
    UIButton *histBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    histBtn.frame = CGRectMake(16, 344, gw, 44);
    histBtn.backgroundColor = [UIColor systemOrangeColor];
    histBtn.layer.cornerRadius = 10;
    histBtn.tintColor = UIColor.whiteColor;
    histBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    [histBtn setTitle:@"📚 历史 dump 管理" forState:UIControlStateNormal];
    [histBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfShowCDHistoryPage") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:histBtn];

    objc_setAssociatedObject(btn, "trio", @[pv, lb, exportBtn, browseBtn], OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    [btn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClassDumpStart:") forControlEvents:UIControlEventTouchUpInside];

    mfPushPage(page);
}

// ====== ZIP 读取器（浏览头文件：central directory 索引 + 按需 inflate，不落双份盘） ======
// MFZipEnt 定义在 MFPanel.h（MFPanel.m 的 Ctrl 方法也要用）

// 索引：不信任 EOCD 条目计数（uint16 截断坑），直接扫 [cdOff, cdOff+cdSize) 区间
NSDictionary *mfZipBuildIndex(NSString *path) {
    FILE *f = fopen(path.fileSystemRepresentation, "rb");
    if (!f) return nil;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    long scan = fsz < 66000 ? fsz : 66000;
    uint8_t *buf = malloc(scan);
    if (!buf || fseek(f, fsz - scan, SEEK_SET) != 0 || fread(buf, 1, scan, f) != (size_t)scan) { free(buf); fclose(f); return nil; }
    long eocd = -1;
    for (long i = scan - 22; i >= 0; i--)
        if (buf[i] == 'P' && buf[i+1] == 'K' && buf[i+2] == 5 && buf[i+3] == 6) { eocd = i; break; }
    if (eocd < 0) { free(buf); fclose(f); return nil; }
    uint32_t cdSize = mfLE32(buf + eocd + 12), cdOff = mfLE32(buf + eocd + 16);
    free(buf);
    if (cdSize == 0 || cdSize > fsz || cdOff >= (unsigned long long)fsz) { fclose(f); return nil; }
    // 兼容 ZIP64：EOCD 字段为哨兵值时经 locator 找 ZIP64 record 读真实值
    if (cdOff == 0xFFFFFFFFu || cdSize == 0xFFFFFFFFu) {
        uint8_t *b2 = malloc(scan);
        fseek(f, fsz - scan, SEEK_SET);
        size_t rd = fread(b2, 1, scan, f);
        long zl = -1;
        for (long i = eocd - 20; i >= 0 && i < (long)rd - 19; i--)
            if (b2[i] == 'P' && b2[i+1] == 'K' && b2[i+2] == 6 && b2[i+3] == 7) { zl = i; break; }
        if (zl >= 0) {
            uint64_t z64Off = 0;
            memcpy(&z64Off, b2 + zl + 8, 8);
            uint8_t zr[56];
            fseek(f, (long)z64Off, SEEK_SET);
            if (fread(zr, 1, 56, f) == 56 && !memcmp(zr, "PK\x06\x06", 4)) {
                memcpy(&cdSize, zr + 40, 8); memcpy(&cdOff, zr + 48, 8);
            }
        }
        free(b2);
    }
    uint8_t *cd = malloc(cdSize);
    if (!cd || fseek(f, (long)cdOff, SEEK_SET) != 0 || fread(cd, 1, cdSize, f) != (size_t)cdSize) { free(cd); fclose(f); return nil; }
    NSMutableDictionary *idx = [NSMutableDictionary dictionaryWithCapacity:70000];
    long p = 0;
    while (p + 46 <= (long)cdSize && !memcmp(cd + p, "PK\x01\x02", 4)) {
        uint16_t method = mfLE16(cd + p + 10);
        uint32_t csize = mfLE32(cd + p + 20), usize = mfLE32(cd + p + 24);
        uint16_t nameLen = mfLE16(cd + p + 28), extraLen = mfLE16(cd + p + 30), commLen = mfLE16(cd + p + 32);
        uint32_t off = mfLE32(cd + p + 42);
        NSString *name = [[NSString alloc] initWithBytes:cd + p + 46 length:nameLen encoding:NSUTF8StringEncoding];
        if (name.length) {
            MFZipEnt e = { off, csize, usize, method };
            idx[name] = [NSValue valueWithBytes:&e objCType:@encode(MFZipEnt)];
        }
        p += 46 + nameLen + extraLen + commLen;
    }
    free(cd); fclose(f);
    return idx;
}

NSData *mfZipReadEntry(NSString *path, const MFZipEnt *e) {
    FILE *f = fopen(path.fileSystemRepresentation, "rb");
    if (!f) return nil;
    uint8_t lh[30];
    if (fseek(f, (long)e->localOff, SEEK_SET) != 0 || fread(lh, 1, 30, f) != 30 || memcmp(lh, "PK\x03\x04", 4)) { fclose(f); return nil; }
    uint16_t nameLen = mfLE16(lh + 26), extraLen = mfLE16(lh + 28);
    fseek(f, (long)nameLen + extraLen, SEEK_CUR);
    uint8_t *cb = malloc(e->csize);
    if (!cb || fread(cb, 1, e->csize, f) != (size_t)e->csize) { free(cb); fclose(f); return nil; }
    fclose(f);
    NSData *comp = [NSData dataWithBytesNoCopy:cb length:e->csize freeWhenDone:YES];
    if (e->method == 0) return comp; // stored
    NSMutableData *out = [NSMutableData dataWithLength:e->usize];
    z_stream zs = {0};
    if (inflateInit2(&zs, -15) != Z_OK) return nil;
    zs.next_in = (Bytef *)comp.bytes; zs.avail_in = e->csize;
    zs.next_out = out.mutableBytes; zs.avail_out = e->usize;
    int rc = inflate(&zs, Z_FINISH);
    inflateEnd(&zs);
    if (rc != Z_STREAM_END) return nil;
    return out;
}

// ====== 列表页（对标 EListVC：搜索过滤 + 点击进详情） ======
@interface MFCDBrowser : NSObject <UITableViewDataSource, UITableViewDelegate, UISearchBarDelegate>
@property (copy) NSString *zipPath;
@property (strong) NSMutableArray<NSString *> *allNames;
@property (copy) NSArray<NSString *> *viewNames;
@property (strong) UITableView *table;
@property (strong) UILabel *status;
@end
@implementation MFCDBrowser
- (void)loadIndex {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *idx = mfZipBuildIndex(self.zipPath);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!idx.count) { self.status.text = @"⚠️ 索引解析失败"; return; }
            self.allNames = [idx.allKeys sortedArrayUsingSelector:@selector(compare:)].mutableCopy;
            self.viewNames = self.allNames;
            self.status.text = [NSString stringWithFormat:@"%lu 个文件", (unsigned long)self.viewNames.count];
            [self.table reloadData];
        });
    });
}
- (void)applyFilter:(NSString *)q {
    NSString *query = [q stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSArray<NSString *> *res = query.length ? [self.allNames filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"SELF CONTAINS[cd] %@", query]] : self.allNames;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.viewNames = res;
            self.status.text = [NSString stringWithFormat:@"%lu 个文件", (unsigned long)res.count];
            [self.table reloadData];
            if (self.table.numberOfSections > 0 && res.count) [self.table scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:0 inSection:0] atScrollPosition:UITableViewScrollPositionTop animated:NO];
        });
    });
}
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return (NSInteger)self.viewNames.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *id_ = @"mfcdrow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:id_];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:id_];
    NSString *n = self.viewNames[ip.row];
    c.textLabel.text = n.lastPathComponent;
    c.textLabel.font = [UIFont systemFontOfSize:13];
    c.detailTextLabel.text = [n hasPrefix:@"swift/"] ? @"swift" : n.stringByDeletingLastPathComponent;
    c.detailTextLabel.font = [UIFont systemFontOfSize:10];
    c.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    mfShowCDFilePage(self.zipPath, self.viewNames[ip.row]);
}
// 左滑「ObC 预填」——类名预填进 ObjC 规则页（v2.6.43 由方法监控改名，链路不变）
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSString *entry = self.viewNames[ip.row];
    __block NSString *cls = entry.lastPathComponent;
    BOOL isSwift = [entry hasPrefix:@"swift/"];
    UIContextualAction *trace = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"🔧 ObjC 预填" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            if (!isSwift) {
                cls = [cls stringByDeletingPathExtension];
                mfTraceSetPrefill(cls);
            }
            mfToast(isSwift ? @"⚠️ Swift 条目无法直接转 ObjC 监控" : [NSString stringWithFormat:@"🔍 已预填 %@", cls]);
            if (!isSwift) mfShowMethodTracePage();
            done(YES);
        }];
    trace.backgroundColor = [UIColor systemPurpleColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[trace]];
}
- (void)searchBar:(UISearchBar *)sb textDidChange:(NSString *)text { [self applyFilter:text]; }
- (void)searchBarSearchButtonClicked:(UISearchBar *)sb { [sb resignFirstResponder]; }
@end

void mfShowCDBrowserPage(NSString *zipPath) {
    UIView *page = mfMakePage(@"📖 头文件", YES);
    CGFloat w = g_mfCardW;

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(16, 44, w - 32, 18)];
    status.font = [UIFont systemFontOfSize:11];
    status.textColor = [UIColor secondaryLabelColor];
    status.text = @"正在读取索引...";
    status.userInteractionEnabled = NO;
    [page addSubview:status];

    UISearchBar *sb = [[UISearchBar alloc] initWithFrame:CGRectMake(8, 64, w - 16, 36)];
    sb.placeholder = @"搜索类名 / 文件名";
    sb.searchBarStyle = UISearchBarStyleMinimal;
    sb.delegate = nil; // 由 controller 接管
    [page addSubview:sb];

    UITableView *tb = [[UITableView alloc] initWithFrame:CGRectMake(0, 102, w, g_mfCardH - 102) style:UITableViewStylePlain];
    tb.backgroundColor = UIColor.clearColor;

    MFCDBrowser *ctl = [MFCDBrowser new];
    ctl.zipPath = zipPath;
    ctl.table = tb;
    ctl.status = status;
    tb.dataSource = ctl; tb.delegate = ctl;
    sb.delegate = ctl;
    objc_setAssociatedObject(page, "ctl", ctl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(sb, "keep", ctl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    [page addSubview:tb];
    mfPushPage(page);
    [ctl loadIndex];
}

// ====== 历史 dump 管理（v1.9.3：列表/浏览/删除） ======
@interface MFCDHistoryList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray<NSDictionary *> *items; // @{path, name, sizeStr, dateStr}
@end
@implementation MFCDHistoryList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return (NSInteger)self.items.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *id_ = @"mfcdhist";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:id_];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:id_];
    NSDictionary *it = self.items[ip.row];
    c.textLabel.text = it[@"name"];
    c.textLabel.font = [UIFont systemFontOfSize:12];
    c.detailTextLabel.text = [NSString stringWithFormat:@"%@ · %@", it[@"sizeStr"], it[@"dateStr"]];
    c.detailTextLabel.font = [UIFont systemFontOfSize:10];
    c.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    c.backgroundColor = UIColor.clearColor;
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    mfShowCDBrowserPage(self.items[ip.row][@"path"]);
}
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSDictionary *it = self.items[ip.row];
    __weak typeof(self) ws = self;
    UIContextualAction *del = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleDestructive
        title:@"🗑 删除" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            NSError *err = nil;
            [[NSFileManager defaultManager] removeItemAtPath:it[@"path"] error:&err];
            mfToast(err ? @"⚠️ 删除失败" : @"🗑️ 已删除");
            NSMutableArray *arr = [ws.items mutableCopy];
            [arr removeObjectAtIndex:ip.row];
            ws.items = arr;
            [tv deleteRowsAtIndexPaths:@[ip] withRowAnimation:UITableViewRowAnimationAutomatic];
            done(YES);
        }];
    return [UISwipeActionsConfiguration configurationWithActions:@[del]];
}
@end

static NSArray<NSDictionary *> *mfCDScanHistory(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0]
                        stringByAppendingPathComponent:@"classdump"];
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
    NSMutableArray<NSDictionary *> *out = [NSMutableArray new];
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"MM-dd HH:mm";
    for (NSString *f in files) {
        if (![f.pathExtension isEqualToString:@"zip"]) continue;
        NSString *p = [dir stringByAppendingPathComponent:f];
        NSDictionary *at = [[NSFileManager defaultManager] attributesOfItemAtPath:p error:nil];
        unsigned long long sz = at.fileSize;
        NSString *szs = sz > 1048576 ? [NSString stringWithFormat:@"%.1f MB", sz / 1048576.0] : [NSString stringWithFormat:@"%llu KB", sz / 1024];
        NSDate *mt = at.fileModificationDate ?: [NSDate distantPast];
        [out addObject:@{@"path": p, @"name": f, @"sizeStr": szs, @"dateStr": [df stringFromDate:mt], @"mtime": @(mt.timeIntervalSince1970)}];
    }
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [b[@"mtime"] compare:a[@"mtime"]]; // 新的在前
    }];
    return out;
}

void mfShowCDHistoryPage(void) {
    UIView *page = mfMakePage(@"📚 历史 dump", YES);
    CGFloat w = g_mfCardW;

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(16, 44, w - 32, 18)];
    status.font = [UIFont systemFontOfSize:11];
    status.textColor = [UIColor secondaryLabelColor];
    [page addSubview:status];

    MFCDHistoryList *ds = [MFCDHistoryList new];
    ds.items = mfCDScanHistory();
    unsigned long long total = 0;
    for (NSDictionary *it in ds.items) total += [[[NSFileManager defaultManager] attributesOfItemAtPath:it[@"path"] error:nil] fileSize];
    status.text = [NSString stringWithFormat:@"%lu 个 zip · 共 %.1f MB · 点击浏览 / 左滑删除",
        (unsigned long)ds.items.count, total / 1048576.0];

    UITableView *tb = [[UITableView alloc] initWithFrame:CGRectMake(0, 66, w, g_mfCardH - 66) style:UITableViewStylePlain];
    tb.backgroundColor = UIColor.clearColor;
    tb.rowHeight = 56;
    tb.dataSource = ds; tb.delegate = ds;
    objc_setAssociatedObject(page, "hists", ds, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [page addSubview:tb];

    if (!ds.items.count) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 120, w - 32, 60)];
        e.text = @"暂无历史记录\n先执行一次 ClassDump";
        e.textAlignment = NSTextAlignmentCenter;
        e.numberOfLines = 2;
        e.textColor = [UIColor tertiaryLabelColor];
        e.font = [UIFont systemFontOfSize:13];
        [page addSubview:e];
    }

    mfPushPage(page);
}

// ====== 详情页（对标 ETextVC：全文查看 + 文内搜索 + 复制 + 分享） ======
@interface MFCDFileViewer : NSObject <UISearchBarDelegate>
@property (copy) NSString *zipPath;
@property (copy) NSString *entryName;
@property (strong) UITextView *tv;
@property (strong) UILabel *hitLabel;
@property (copy) NSString *content;
@property (strong) NSMutableArray<NSValue *> *hits;
@property (assign) NSInteger hitIdx;
@end
@implementation MFCDFileViewer
- (void)load {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *idx = mfZipBuildIndex(self.zipPath);
        NSValue *v = idx[self.entryName];
        NSData *data = v ? nil : nil;
        if (v) {
            MFZipEnt e; [v getValue:&e];
            data = mfZipReadEntry(self.zipPath, &e);
        }
        NSString *txt = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                             ?: [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"⚠️ 解压失败";
        dispatch_async(dispatch_get_main_queue(), ^{
            self.content = txt ?: @"";
            self.tv.text = self.content;
        });
    });
}
- (void)jumpTo:(NSInteger)i {
    if (!self.hits.count) return;
    NSInteger j = ((i % (NSInteger)self.hits.count) + self.hits.count) % self.hits.count;
    self.hitIdx = j;
    NSRange r = [self.hits[j] rangeValue];
    [self.tv scrollRangeToVisible:r];
    self.tv.selectedRange = r;
    self.hitLabel.text = [NSString stringWithFormat:@"%ld/%lu", (long)(j + 1), (unsigned long)self.hits.count];
}
- (void)findHits:(NSString *)q {
    self.hits = [NSMutableArray array];
    self.hitIdx = -1;
    if (q.length && self.content) {
        NSString *c = self.content;
        NSRange r = NSMakeRange(0, c.length);
        @autoreleasepool {
            while (r.location != NSNotFound && self.hits.count < 500) {
                NSRange f = [c rangeOfString:q options:NSCaseInsensitiveSearch range:r];
                if (f.location == NSNotFound) break;
                [self.hits addObject:[NSValue valueWithRange:f]];
                r = NSMakeRange(f.location + f.length, c.length - f.location - f.length);
                if ((NSInteger)r.length < 0) break;
            }
        }
    }
    self.hitLabel.text = self.hits.count ? [NSString stringWithFormat:@"1/%lu", (unsigned long)self.hits.count] : @"0";
    if (self.hits.count) [self jumpTo:0]; else self.hitLabel.text = @"0";
}
- (void)next:(UIButton *)b { [self jumpTo:self.hitIdx + 1]; }
- (void)prev:(UIButton *)b { [self jumpTo:self.hitIdx - 1]; }
- (void)searchBar:(UISearchBar *)sb textDidChange:(NSString *)t { [self findHits:t]; }
- (void)searchBarSearchButtonClicked:(UISearchBar *)sb { [sb resignFirstResponder]; }
@end

// 复制/分享逻辑在 MFPanel.m 的 Ctrl 方法里实现（从 sender 的 "viewer" associated 取上下文）

void mfShowCDFilePage(NSString *zipPath, NSString *entryName) {
    UIView *page = mfMakePage(entryName.lastPathComponent, YES);
    CGFloat w = g_mfCardW;

    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(0, 42, w, g_mfCardH - 130)];
    tv.editable = NO;
    tv.font = [UIFont fontWithName:@"Menlo-Regular" size:10] ?: [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    tv.backgroundColor = UIColor.clearColor;
    tv.autocorrectionType = UITextAutocorrectionTypeNo;
    [page addSubview:tv];

    // 底部工具行：文内搜索 ‹ n/m › | 复制 | 分享
    CGFloat by = g_mfCardH - 84;
    UISearchBar *sb = [[UISearchBar alloc] initWithFrame:CGRectMake(4, by, w - 190, 36)];
    sb.placeholder = @"文内搜索";
    sb.searchBarStyle = UISearchBarStyleMinimal;
    [page addSubview:sb];

    UIButton *prevB = [UIButton buttonWithType:UIButtonTypeSystem];
    prevB.frame = CGRectMake(w - 184, by + 2, 30, 30);
    [prevB setTitle:@"‹" forState:UIControlStateNormal];
    prevB.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    [page addSubview:prevB];

    UILabel *hitLb = [[UILabel alloc] initWithFrame:CGRectMake(w - 154, by + 6, 44, 22)];
    hitLb.font = [UIFont systemFontOfSize:11];
    hitLb.textColor = [UIColor secondaryLabelColor];
    hitLb.textAlignment = NSTextAlignmentCenter;
    hitLb.text = @"0";
    [page addSubview:hitLb];

    UIButton *nextB = [UIButton buttonWithType:UIButtonTypeSystem];
    nextB.frame = CGRectMake(w - 112, by + 2, 30, 30);
    [nextB setTitle:@"›" forState:UIControlStateNormal];
    nextB.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    [page addSubview:nextB];

    UIButton *copyB = [UIButton buttonWithType:UIButtonTypeSystem];
    copyB.frame = CGRectMake(w - 78, by + 2, 34, 30);
    [copyB setTitle:@"📋" forState:UIControlStateNormal];
    [page addSubview:copyB];

    UIButton *shareB = [UIButton buttonWithType:UIButtonTypeSystem];
    shareB.frame = CGRectMake(w - 42, by + 2, 38, 30);
    [shareB setTitle:@"⤴" forState:UIControlStateNormal];
    shareB.titleLabel.font = [UIFont systemFontOfSize:17];
    [page addSubview:shareB];

    MFCDFileViewer *ctl = [MFCDFileViewer new];
    ctl.zipPath = zipPath;
    ctl.entryName = entryName;
    ctl.tv = tv; ctl.hitLabel = hitLb; ctl.hits = [NSMutableArray array];
    sb.delegate = ctl;
    [prevB addTarget:ctl action:NSSelectorFromString(@"prev:") forControlEvents:UIControlEventTouchUpInside];
    [nextB addTarget:ctl action:NSSelectorFromString(@"next:") forControlEvents:UIControlEventTouchUpInside];
    objc_setAssociatedObject(page, "ctl", ctl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(copyB, "viewer", ctl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(shareB, "viewer", ctl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [copyB addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCDFileCopy:") forControlEvents:UIControlEventTouchUpInside];
    [shareB addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCDFileShare:") forControlEvents:UIControlEventTouchUpInside];

    mfPushPage(page);
    [ctl load];
}
