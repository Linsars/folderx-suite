// One-shot black-box oracle for ReflixPatch 3.0.5.
// Why: diff the target's executable memory before/after vendor patch loading;
// this recovers exact app offsets without reversing flattened control flow.

#import "MFPanel.h"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <unistd.h>

static NSString *const kOracleBID = @"com.magicgroot.gooby";
static NSString *const kOracleVersion = @"3.0.5";
static NSString *const kOracleDylib = @"/var/jb/usr/lib/MinisFix/ReflixPatch-3.0.5.dylib";

static NSString *mfHex(const uint8_t *p, size_t n) {
    static const char h[] = "0123456789abcdef";
    if (!p || !n) return @"";
    char *s = malloc(n * 2 + 1);
    if (!s) return nil;
    for (size_t i = 0; i < n; i++) {
        s[i * 2] = h[p[i] >> 4];
        s[i * 2 + 1] = h[p[i] & 15];
    }
    s[n * 2] = 0;
    NSString *r = [NSString stringWithUTF8String:s];
    free(s);
    return r;
}

static BOOL mfFindText(const struct mach_header_64 *mh, intptr_t slide,
                       const uint8_t **memOut, uint64_t *sizeOut,
                       uint64_t *fileOut, uint64_t *imageOut,
                       NSString **diagOut) {
    if (!mh || mh->magic != MH_MAGIC_64) {
        if (diagOut) *diagOut = [NSString stringWithFormat:@"bad mh: %p magic=0x%x", mh, mh ? mh->magic : 0];
        return NO;
    }
    const uint8_t *p = (const uint8_t *)(mh + 1);
    uint64_t textVM = 0;
    uint64_t hitAddr = 0, hitSize = 0, hitOff = 0;
    int found = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(*lc)) {
            if (diagOut) *diagOut = [NSString stringWithFormat:@"bad cmdsize %u at %u", lc->cmdsize, i];
            return NO;
        }
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
            if (!strncmp(sg->segname, SEG_TEXT, 16)) {
                textVM = sg->vmaddr;
                const struct section_64 *sc = (const struct section_64 *)(sg + 1);
                for (uint32_t j = 0; j < sg->nsects; j++) {
                    if (!strncmp(sc[j].sectname, SECT_TEXT, 16)) {
                        hitAddr = sc[j].addr;
                        hitSize = sc[j].size;
                        hitOff = sc[j].offset;
                        found = 1;
                    }
                }
            }
        }
        p += lc->cmdsize;
    }
    if (!found || !hitSize) {
        if (diagOut) *diagOut = [NSString stringWithFormat:@"not found: found=%d textVM=0x%llx hitSize=0x%llx ncmds=%u",
                                 found, textVM, hitSize, mh->ncmds];
        return NO;
    }
    // Note: in ASLR/pie Mach-O, textVM is usually 0x100000000.
    // Memory address is (uintptr_t)mh + (hitAddr - textVM).
    *memOut = (const uint8_t *)((uintptr_t)mh + (hitAddr >= textVM ? (hitAddr - textVM) : hitAddr));
    *sizeOut = hitSize;
    *fileOut = hitOff;
    *imageOut = hitAddr >= textVM ? (hitAddr - textVM) : hitAddr;
    return YES;
}

static void mfWriteOracleReport(NSDictionary *report) {
    if (!report) return;
    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MinisFix"];
    NSError *e = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES
                                                   attributes:nil error:&e]) return;
    NSMutableDictionary *mut = [report mutableCopy];
    mut[@"timestamp"] = [NSDate date].description;
    NSData *d = [NSJSONSerialization dataWithJSONObject:mut
                                                options:NSJSONWritingPrettyPrinted error:&e];
    if (!d || e) return;
    [d writeToFile:[dir stringByAppendingPathComponent:@"reflix_oracle.json"] atomically:YES];
}

void mfReflixOracleStart(void) {
    NSString *bid = [NSBundle mainBundle].bundleIdentifier;
    NSString *ver = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    if (![bid isEqualToString:kOracleBID] || ![ver isEqualToString:kOracleVersion]) return;

    // v2.26.1: A/B 实测 dylib 已退役(mock 独立亮) — oracle dlopen 退役, 默认不再拉尸入膛
    if (![[NSUserDefaults standardUserDefaults] boolForKey:@"mfOracleEnabled"]) return;

    // Locate the actual MH_EXECUTE main binary image
    const struct mach_header_64 *mh = NULL;
    intptr_t slide = 0;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE) {
            mh = (const struct mach_header_64 *)h;
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!mh) {
        mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
        slide = _dyld_get_image_vmaddr_slide(0);
    }

    const uint8_t *text = NULL;
    uint64_t textSize = 0, fileBase = 0, imageBase = 0;
    NSString *diag = nil;
    if (!mfFindText(mh, slide, &text, &textSize, &fileBase, &imageBase, &diag)) {
        mfWriteOracleReport(@{
            @"ok": @NO,
            @"error": [NSString stringWithFormat:@"main __text not found: %@", diag ?: @"unknown"]
        });
        return;
    }
    if (textSize > 96ULL * 1024 * 1024) {
        mfWriteOracleReport(@{@"ok": @NO, @"error": @"main __text too large"});
        return;
    }
    uint8_t *before = malloc((size_t)textSize);
    if (!before) {
        mfWriteOracleReport(@{@"ok": @NO, @"error": @"snapshot allocation failed"});
        return;
    }
    memcpy(before, text, (size_t)textSize);

    void *handle = dlopen(kOracleDylib.UTF8String, RTLD_NOW | RTLD_LOCAL);
    const char *de = handle ? NULL : dlerror();
    if (!handle) {
        NSString *err = de ? [NSString stringWithUTF8String:de] : @"dlopen failed";
        free(before);
        mfWriteOracleReport(@{@"ok": @NO, @"error": err ?: @"dlopen failed"});
        mfLog(@"[oracle] load failed");
        return;
    }

    // Some patchers dispatch from image callbacks/worker threads.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableArray *ranges = [NSMutableArray array];
        uint64_t changed = 0;
        for (uint64_t i = 0; i < textSize;) {
            if (before[i] == text[i]) { i++; continue; }
            uint64_t start = i;
            while (i < textSize && before[i] != text[i]) i++;
            uint64_t len = i - start;
            changed += len;
            // Preserve full short patches; cap only pathological blocks.
            uint64_t keep = MIN(len, 256ULL);
            [ranges addObject:@{
                @"file_offset": [NSString stringWithFormat:@"0x%llx", fileBase + start],
                @"image_offset": [NSString stringWithFormat:@"0x%llx", imageBase + start],
                @"length": @(len),
                @"before": mfHex(before + start, (size_t)keep) ?: @"",
                @"after": mfHex(text + start, (size_t)keep) ?: @""
            }];
            if (ranges.count >= 4096) break;
        }
        NSDictionary *r = @{
            @"ok": @YES,
            @"bundle_id": bid,
            @"version": ver,
            @"text_size": [NSString stringWithFormat:@"0x%llx", textSize],
            @"changed_bytes": @(changed),
            @"ranges": ranges
        };
        mfWriteOracleReport(r);
        mfLog(@"[oracle] patch loaded; text diff ranges=%lu bytes=%llu",
              (unsigned long)ranges.count, changed);
        free(before);
    });
}
