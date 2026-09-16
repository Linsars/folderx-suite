// MFDiagnostics.m — T0 金矿开采 (v1.6.0 新增)
// 思路来源：ToolsEric UCPTMachODeepVC(MachO深检) 方法表逆向，
// 实现全部自研。零第三方依赖。

#import "MFPanel.h"
#import <Security/Security.h>
#import <mach-o/dyld.h>
// SecTask 私有 API（同 MFKeychainManager.m，SDK 未公开头文件）
typedef struct CF_BRIDGED_TYPE(id) OpaqueSecTaskRef *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef entitlement, CFErrorRef *error);
// 本地 nlist_64（绕开 modules 与 loader.h 的定义冲突）
struct mf_nlist_64 { uint32_t n_strx; uint8_t n_type; uint8_t n_sect; uint16_t n_desc; uint64_t n_value; };
#include <sys/sysctl.h>
#include <sys/types.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>
#include <dlfcn.h>

// csops 系统调用（不引私有头）
#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif
#define MF_CS_VALID        0x00000001
#define MF_CS_ADHOC        0x00000002
#define MF_CS_GET_TASK_ALLOW 0x00000004
#define MF_CS_DEBUGGED     0x00000010
#define MF_CS_KILL         0x00000200
#define MF_CS_RESTRICT     0x00000800
#define MF_CS_PLATFORM_BINARY 0x04000000

extern char **environ;

#pragma mark - ====== MachO 深检 ======

// 主二进制解析：读文件头 + load commands（进程内自读，无需注入）
static NSData *mfMainBinaryData(void) {
    NSString *p = [[NSBundle mainBundle] executablePath];
    return p ? [NSData dataWithContentsOfFile:p options:NSDataReadingMappedAlways error:nil] : nil;
}

// 定长 char[N] 字段安全转 NSString（segname/sectname 不保证 \0 结尾，直接 %@ 会越界读）
static NSString *mfFixedStr(const char *src, size_t n) {
    char buf[17];
    memcpy(buf, src, MIN(n, 16));
    buf[MIN(n, 16)] = 0;
    return [NSString stringWithUTF8String:buf] ?: @"?";
}

NSString *mfMachOSections(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【Sections】\n"];
    NSData *d = mfMainBinaryData();
    if (!d) return @"⚠️ 无法读取主二进制";
    const uint8_t *b = d.bytes;
    const uint8_t *end = b + d.length;
    if (d.length < sizeof(struct mach_header_64) || *(const uint32_t *)b != MH_MAGIC_64)
        return @"⚠️ 非 64 位 Mach-O";
    struct mach_header_64 mh;
    memcpy(&mh, b, sizeof(mh));
    [r appendFormat:@"  cputype=%x ncmds=%u filetype=%u\n", (unsigned)mh.cputype, mh.ncmds, (unsigned)mh.filetype];
    const uint8_t *p = b + sizeof(mh);
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (p + sizeof(struct load_command) > end) { [r appendString:@"  ⚠️ 越界截断\n"]; break; }
        struct load_command lc; memcpy(&lc, p, sizeof(lc));
        if (lc.cmdsize < sizeof(lc) || p + lc.cmdsize > end) { [r appendString:@"  ⚠️ cmdsize 异常截断\n"]; break; }
        if (lc.cmd == LC_SEGMENT_64 && p + sizeof(struct segment_command_64) <= end) {
            struct segment_command_64 sg; memcpy(&sg, p, sizeof(sg));
            [r appendFormat:@"▸ %@ (vmaddr=%llx)\n", mfFixedStr(sg.segname, 16), sg.vmaddr];
            const uint8_t *sp = p + sizeof(sg);
            for (uint32_t j = 0; j < sg.nsects; j++) {
                if (sp + (j + 1) * sizeof(struct section_64) > end) break;
                struct section_64 sec; memcpy(&sec, sp + j * sizeof(sec), sizeof(sec));
                [r appendFormat:@"  · %@,%@ off=%-6u size=%-7u flags=%x\n",
                    mfFixedStr(sec.segname, 16), mfFixedStr(sec.sectname, 16),
                    (unsigned)sec.offset, (unsigned)sec.size, (unsigned)sec.flags];
            }
        }
        p += lc.cmdsize;
    }
    return r;
}

NSString *mfMachODylibs(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【Dylib 依赖】\n"];
    NSData *d = mfMainBinaryData();
    const uint8_t *b = d.bytes;
    const uint8_t *end = b + (d ? d.length : 0);
    if (!d || d.length < sizeof(struct mach_header_64) || *(const uint32_t *)b != MH_MAGIC_64) return @"⚠️ 解析失败";
    struct mach_header_64 mh; memcpy(&mh, b, sizeof(mh));
    const uint8_t *p = b + sizeof(mh);
    int n = 0;
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (p + sizeof(struct load_command) > end) break;
        struct load_command lc; memcpy(&lc, p, sizeof(lc));
        if (lc.cmdsize < sizeof(lc) || p + lc.cmdsize > end) break;
        if ((lc.cmd == LC_LOAD_WEAK_DYLIB || LC_LOAD_DYLIB == lc.cmd) && p + sizeof(struct dylib_command) <= end) {
            struct dylib_command dc; memcpy(&dc, p, sizeof(dc));
            // name offset 指向 LC 内字符串区，校验后按 %s 打印（null-terminated 保证）
            uint32_t noff = dc.dylib.name.offset;
            if (noff > 0 && noff < lc.cmdsize) {
                const char *nm = (const char *)p + noff;
                [r appendFormat:@"  %@ %.200s\n", lc.cmd == LC_LOAD_WEAK_DYLIB ? @"🟡(weak)" : @"·", nm];
                n++;
            }
        }
        p += lc.cmdsize;
    }
    [r appendFormat:@"  共 %d 个依赖\n", n];
    return r;
}

NSString *mfMachOStrings(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【__cstring 抽样】\n"];
    unsigned long sz = 0;
    // 必须传主镜像 header——getsectiondata(NULL) 是未定义行为（闪退点）
    const struct mach_header_64 *hdr = _dyld_get_image_header(0);
    const uint8_t *cs = hdr ? getsectiondata(hdr, "__TEXT", "__cstring", &sz) : NULL;
    if (!cs || !sz) return @"⚠️ __cstring 未找到";
    [r appendFormat:@"  段大小: %lu bytes\n", sz];
    // 抽样前 60 条可读字符串
    int shown = 0, i = 0;
    while (i < (int)sz && shown < 60) {
        const char *s = (const char *)cs + i;
        size_t len = strnlen(s, sz - i);
        if (len >= 6 && len <= 120 && isprint((unsigned char)s[0])) {
            int alpha = 0;
            for (size_t k = 0; k < len && k < 40; k++) if (isalpha((unsigned char)s[k])) alpha++;
            if (alpha > len / 2) {
                [r appendFormat:@"  %.*s\n", (int)MIN(len, 100), s];
                shown++;
            }
        }
        i += (int)(len + 1);
    }
    return r;
}

NSString *mfMachOSymbols(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【符号表概览】\n"];
    NSData *d = mfMainBinaryData();
    const uint8_t *b = d.bytes;
    const uint8_t *end = b + (d ? d.length : 0);
    if (!d || d.length < sizeof(struct mach_header_64) || *(const uint32_t *)b != MH_MAGIC_64) return @"⚠️ 解析失败";
    struct mach_header_64 mh; memcpy(&mh, b, sizeof(mh));
    const uint8_t *p = b + sizeof(mh);
    struct symtab_command st = {0};
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (p + sizeof(struct load_command) > end) break;
        struct load_command lc; memcpy(&lc, p, sizeof(lc));
        if (lc.cmdsize < sizeof(lc) || p + lc.cmdsize > end) break;
        if (lc.cmd == LC_SYMTAB && p + sizeof(st) <= end) memcpy(&st, p, sizeof(st));
        p += lc.cmdsize;
    }
    if (!st.cmd) return @"⚠️ 无 LC_SYMTAB（stripped）";
    // symoff/stroff 边界校验后再解引用
    if (st.symoff >= d.length || st.stroff >= d.length ||
        (unsigned long long)st.symoff + (unsigned long long)st.nsyms * sizeof(struct mf_nlist_64) > d.length)
        return @"⚠️ 符号表偏移越界（可能被 strip 工具破坏）";
    [r appendFormat:@"  符号总数: %u\n", st.nsyms];
    struct mf_nlist_64 nl;
    int shown = 0;
    for (uint32_t i = 0; i < st.nsyms && shown < 50; i++) {
        memcpy(&nl, b + st.symoff + i * sizeof(nl), sizeof(nl));
        if (!nl.n_strx) continue;
        uint32_t off = st.stroff + nl.n_strx;
        if (off >= d.length) continue;
        const char *s = (const char *)b + off;
        if (!isprint((unsigned char)s[0])) continue;
        size_t slen = strnlen(s, d.length - off);
        [r appendFormat:@"  %.*s\n", (int)MIN(slen, 120), s];
        shown++;
    }
    if (st.nsyms > 50) [r appendFormat:@"  …（共 %u 条）\n", st.nsyms];
    return r;
}

NSString *mfMachORuntime(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【ObjC 运行时】\n"];
    unsigned total = objc_getClassList(NULL, 0);
    __unsafe_unretained Class *classes = (__unsafe_unretained Class *)malloc(total * sizeof(Class));
    unsigned got = classes ? objc_getClassList(classes, total) : 0;
    NSString *myEx = [[NSBundle mainBundle] executablePath].lastPathComponent;
    NSMutableSet *myClasses = [NSMutableSet set];
    for (unsigned i = 0; i < got; i++) {
        const char *img = class_getImageName(classes[i]);
        if (!img) continue;
        NSString *ip = [NSString stringWithUTF8String:img];
        if (![ip.lastPathComponent containsString:myEx]) continue;
        [myClasses addObject:NSStringFromClass(classes[i])];
    }
    free(classes);
    unsigned protoCount = 0;
    Protocol *__unsafe_unretained *protos = objc_copyProtocolList(&protoCount);
    if (protos) free(protos);
    [r appendFormat:@"  本 App 类数: %lu（全进程 %u）\n", (unsigned long)myClasses.count, total];
    [r appendFormat:@"  全进程协议: %u\n", protoCount];
    // 类名抽样前 30
    NSArray *sorted = [myClasses.allObjects sortedArrayUsingSelector:@selector(compare:)];
    for (NSUInteger i = 0; i < sorted.count && i < 30; i++) [r appendFormat:@"    @interface %@\n", sorted[i]];
    if (myClasses.count > 30) [r appendFormat:@"    …（共 %lu）\n", (unsigned long)myClasses.count];
    return r;
}

#pragma mark - ====== 通用文本报告页（对标 UCPTTextViewController） ======

void mfShowTextReportPage(NSString *title, NSString *text, NSString *exportName) {
    UIView *page = mfMakePage(title, YES);
    CGFloat w = g_mfCardW;

    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(0, 42, w, g_mfCardH - 92)];
    tv.editable = NO;
    tv.font = [UIFont fontWithName:@"Menlo-Regular" size:11] ?: [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    tv.backgroundColor = UIColor.clearColor;
    tv.text = text;
    tv.autocorrectionType = UITextAutocorrectionTypeNo;
    [page addSubview:tv];

    CGFloat by = g_mfCardH - 46;
    UIButton *copyB = [UIButton buttonWithType:UIButtonTypeSystem];
    copyB.frame = CGRectMake(w - 170, by, 78, 36);
    copyB.backgroundColor = [UIColor secondarySystemBackgroundColor];
    copyB.layer.cornerRadius = 10;
    [copyB setTitle:@"📋 复制" forState:UIControlStateNormal];
    [page addSubview:copyB];

    UIButton *shareB = [UIButton buttonWithType:UIButtonTypeSystem];
    shareB.frame = CGRectMake(w - 84, by, 78, 36);
    shareB.backgroundColor = [UIColor systemBlueColor];
    shareB.layer.cornerRadius = 10;
    shareB.tintColor = UIColor.whiteColor;
    [shareB setTitle:@"⤴ 分享" forState:UIControlStateNormal];
    [page addSubview:shareB];

    objc_setAssociatedObject(page, "text", text, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "name", exportName, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(copyB, "page", page, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(shareB, "page", page, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [copyB addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDiagCopy:") forControlEvents:UIControlEventTouchUpInside];
    [shareB addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDiagShare:") forControlEvents:UIControlEventTouchUpInside];

    mfPushPage(page);
}

void mfShowMachODeepPage(void) {
    UIView *page = mfMakePage(@"🔬 MachO 深检", YES);
    CGFloat gw = g_mfCardW - 32;
    NSString *exPath = [[NSBundle mainBundle] executablePath];
    NSDictionary *at = [[NSFileManager defaultManager] attributesOfItemAtPath:exPath error:nil];
    UILabel *info = [[UILabel alloc] initWithFrame:CGRectMake(16, 44, gw, 44)];
    info.font = [UIFont systemFontOfSize:11];
    info.textColor = [UIColor secondaryLabelColor];
    info.numberOfLines = 2;
    info.text = [NSString stringWithFormat:@"%@\n%.1f MB", exPath.lastPathComponent,
                 [at[NSFileSize] doubleValue] / 1048576.0];
    [page addSubview:info];

    NSArray *items = @[
        @[@"Sections 全览", @"sec"], @[@"Dylib 依赖", @"dylib"],
        @[@"__cstring 抽样", @"str"], @[@"符号表概览", @"sym"],
        @[@"ObjC 运行时归属", @"rt"],
    ];
    CGFloat y = 96;
    for (NSArray *it in items) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(16, y, gw, 42);
        b.backgroundColor = [UIColor secondarySystemBackgroundColor];
        b.layer.cornerRadius = 10;
        b.tintColor = [UIColor labelColor];
        b.titleLabel.font = [UIFont systemFontOfSize:13];
        [b setTitle:[@"▸ " stringByAppendingString:it[0]] forState:UIControlStateNormal];
        objc_setAssociatedObject(b, "kind", it[1], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [page addSubview:b];
        [b addTarget:g_mfCtrl action:NSSelectorFromString(@"mfMachORun:") forControlEvents:UIControlEventTouchUpInside];
        y += 50;
    }
    mfPushPage(page);
}
