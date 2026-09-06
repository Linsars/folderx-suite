// MFPanel.h — MinisFix v5.0 面板系统头文件
// 三板块：数据分析 / 网络修改 / Product
// 呼出：双指长按

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

// ====== 全局状态 ======
extern UIView *g_mfPanelOverlay;
extern UIViewController *g_mfPanelRootVC;
extern id g_mfCtrl;
extern NSMutableArray *g_mfPages;
extern CGFloat g_mfCardW, g_mfCardH;
extern UIView *g_mfCardContentView;
extern UIView *g_mfHomePage;
extern UIVisualEffectView *g_mfCardView;
extern CGFloat g_mfHomeCardH;
void mfSetCardHeight(CGFloat h);

// ====== 轻提示 ======
void mfToast(NSString *msg);

// ====== 日志 ======
void mfLog(NSString *fmt, ...);
#define MFLOG(fmt, ...) mfLog(fmt, ##__VA_ARGS__)

// ====== Prefs ======
NSDictionary *mfPrefsDict(void);
BOOL mfPrefBool(NSString *key, BOOL def);
void mfSetBoolPref(NSString *key, BOOL val);
void mfSetPrefDouble(NSString *key, double val);
double mfPrefDouble(NSString *key, double def);

// ====== 面板导航（定义在 MFPanel.m） ======
UIView *mfMakePage(NSString *title, BOOL showBack);
void mfPushPage(UIView *page);
void mfPopPage(void);
void mfClosePanel(void);
CGFloat mfGridButton(UIView *card, CGFloat x, CGFloat y, CGFloat w, NSString *title, NSString *emoji, SEL action, BOOL switchMode, NSString *pfx);
void mfAttachKbBar(id field);                               // v2.7.1 键盘收起工具条（UITextField/UITextView 通吃）
void mfCopyText(NSString *text, NSString *toastMsg);        // v2.7.2 复制到剪贴板 + 可选 toast
UIViewController *mfTopVC(void);                            // v2.7.2 最顶层 VC 定位（keyWindow + presented 链）
UIButton *mfRowButton(UIView *parent, CGFloat x, CGFloat y, CGFloat w, CGFloat h, NSString *title, UIColor *bg, SEL action); // v2.7.2 行按钮

// ====== 功能页面入口（各模块 .m 定义） ======
// 数据分析（MFNetworkCapture.m）
void mfShowDataAnalysisPage(void);    // 实时捕获网络请求 + 数据解密
void mfShowNetworkCapturePage(void);   // 网络捕获列表
void mfShowCryptoToolboxPage(void);    // 解密工具箱

// 网络修改（MFNetworkCapture.m）
void mfShowNetworkModifyPage(void);    // 拦截规则列表 + 开关
void mfInstallNetworkCapture(void);     // 安装 NSURLProtocol（ctor 调用）

// Product（IAPHunter）（MFPanel.m）
void mfShowProductPage(void);          // 扫描购买 / 手动购买 / 图标解锁
void mfShowScanPage(void);
void mfShowLabPage(void);              // 🧪 实验模拟(订阅注入/收据伪造)
BOOL mfL0IsOn(void); long mfL0ObserverCount(void); void mfL0SetOn(BOOL on); // L0 队列伪造
void mfShowManualBuyPage(void);
void mfShowIconPage(void);

// Keychain（MFKeychainManager.m）
void mfShowKeychainManagerPage(void);       // Keychain 主页
void mfShowKeychainListPageAction(void);    // 查看列表
void mfCopyKeychainAction(void);            // 导出到剪贴板

// ClassDump（MFClassDump.m）— v1.5.0 数据分析板块
void mfShowClassDumpPage(void);             // ClassDump 页
void mfClassDumpStartAction(UIProgressView *pv, UILabel *lb, UIButton *btn, UIView *actionRow);
void mfShowRestorePromptAction(void);       // 从剪贴板恢复
void mfShowKeychainDetail(NSDictionary *item); // 详情面板 (由 MFPanelCtrl 转发)
void mfDumpCurrentAppKeychain(void);           // Dump 当前 App Keychain（取证）
void mfCopyDumpJsonFromButton(UIButton *btn);  // 复制 Dump JSON（按钮）
void mfKeychainDataDisplayFromButton(UIButton *btn);    // 详情：Base64/Hex/UTF8 切换
void mfCopyKeychainDataFromDetailButton(UIButton *btn); // 详情：复制数据
void mfEditKeychainDataFromDetailButton(UIButton *btn); // 详情：编辑/保存数据
void mfDoRestoreFromPageButton(UIButton *btn);          // 恢复页：执行恢复
void mfKbSaveAndDismissFromBar(UIBarButtonItem *item);  // 键盘工具条：保存并收起
void mfKbDismissKeyboardFromBar(UIBarButtonItem *item); // 键盘工具条：收起

// ====== 捕获数据模型 ======
@interface MFNetRecord : NSObject
@property (copy) NSString *url;
@property (copy) NSString *method;
@property (copy) NSDictionary *reqHeaders;
@property (copy) NSData *reqBody;
@property (copy) NSDictionary *respHeaders;
@property (copy) NSData *respBody;
@property NSInteger status;
@property (copy) NSString *mimeType;
@property (strong) NSDate *timestamp;
@property (copy) NSString *summary;
@end
void mfShowCaptureDetailPage(MFNetRecord *rec);

// ====== 拦截规则模型（实现 MFNetworkCapture.m） ======
// 规则隔离：appBundle 非空时只对创建它的 app 生效
@interface MFRewriteRule : NSObject
@property (copy) NSString *pattern;
@property (copy) NSString *matchType;    // url / regex / contain
@property (copy) NSString *action;       // block / replaceReq / replaceResp  (legacy)
@property (copy) NSString *urlReplace;
@property (copy) NSString *bodyReplace;  // legacy
@property (copy) NSDictionary *headerReplaces; // legacy
@property (copy) NSString *direction;    // request / response / nil(双向)
@property (assign) BOOL reject;          // 屏蔽/拒绝（替代旧 block）
@property (copy) NSString *name;         // 规则备注
@property (copy) NSDictionary *reqHeaders;
@property (copy) NSDictionary *respHeaders;
@property (copy) NSString *reqBody;
@property (copy) NSString *respBody;
@property (assign) BOOL enabled;
@property (copy) NSString *appBundle;
- (NSDictionary *)toDict;
+ (instancetype)fromDict:(NSDictionary *)d;
@end
void mfSaveRule(MFRewriteRule *rule, NSInteger index);   // index<0 追加
void mfRemoveRule(NSInteger index);
NSString *mfCurrentBundleId(void);
void mfShowRuleEditPage(NSString *pattern, NSString *action, NSInteger index, BOOL fromList);

// ====== 诊断日志清理（MFDiagnosticCleaner.m） ======
void mfDiagnosticCleanupFromSettings(void);

// ====== Keychain 管理（MFKeychainManager.m） ======
void mfShowKeychainManagerPage(void);
void mfCopyICloudRecordIDFromCell(UIViewController *vc, UIView *cell);

// ====== ClassDump 浏览器（MFClassDump.m） ======
typedef struct { uint32_t localOff; uint32_t csize; uint32_t usize; uint16_t method; } MFZipEnt;
NSDictionary *mfZipBuildIndex(NSString *path);                 // @{name: NSValue(MFZipEnt)}
NSData *mfZipReadEntry(NSString *path, const MFZipEnt *e);     // 按需解压单条目
void mfShowCDBrowserPage(NSString *zipPath);                   // 文件列表 + 搜索
void mfShowCDHistoryPage(void);                                // 历史 dump 管理（浏览/删除）
void mfShowCDFilePage(NSString *zipPath, NSString *entry);     // 单文件查看 + 文内搜索

// ====== 诊断（MFDiagnostics.m） ======
void mfShowMachODeepPage(void);           // MachO 深检
void mfShowTextReportPage(NSString *title, NSString *text, NSString *exportName); // 通用文本报告页
NSString *mfMachOSections(void);
NSString *mfMachODylibs(void);
NSString *mfMachOStrings(void);
NSString *mfMachOSymbols(void);
NSString *mfMachORuntime(void);

// ====== 解密工具箱 v2（MFCryptoToolbox.m） ======
void mfShowCryptoToolboxPage(void);
void mfCryptoBuildChips(UIScrollView *scroll, int group);
void mfCryptoGroupChangedAction(UISegmentedControl *seg);
void mfCryptoChipTappedAction(UIButton *chip);
void mfCryptoRunAction(UIButton *btn);

// ====== T1 解密捕获（MFCryptoHooks.m） ======
void mfShowCryptoCapturePage(void);          // 捕获列表页（含开关/清空）
void mfCryptoCapSwitchChanged(UISwitch *sw); // C 函数，Ctrl wrapper 转发
void mfCryptoClearTapped(void);
BOOL mfCryptoEnabledState(void);             // 定义在 MFCryptoHooks.m
NSArray *mfCryptoRecordsSnapshot(void);
void mfInstallCryptoHooks(void);             // 首次开启时安装 CCCrypt/HMAC hooks

// ====== T1 方法监控（MFMethodTrace.m） ======
void mfShowMethodTracePage(void);
void mfTraceSetPrefill(NSString *cls);                         // 左滑头文件预填类名(保留别名)
void mfShowObjCHookPage(void);                                 // 🔧 ObjC 规则(精确 hook, 取代方法监控)
void mfObjCHookApply(void);
void mfObjCHookApplySilent(void);   // ctor 静默应用
void mfObjCHookStop(void);
void mfObjCHookFormAddTapped(void);
void mfObjCForceSandboxTapped(void);   // 🧪 强制 sandbox(私有 API)
void mfObjCTxProbeTapped(void);   // 🧪 伪造交易实验
void mfSubInjectSwitchChanged(UISwitch *sw); // 📡 订阅 SDK 响应注入开关 (MFSubInject.m)
void mfSubInjectAutoStart(void);
NSArray *mfSubPids(void);                // 扫描列表商品 ID (MFSubInject.m, 收据层共用)
void mfFileIDsAdd(NSString *pid);   // v2.11.8 文件级 ID 存储 (MFSubInject.m)
void mfReceiptForgeSwitchChanged(UISwitch *sw); // 🧾 收据伪造开关 (MFReceiptForge.m)
void mfReceiptForgeAutoStart(void);
void mfReceiptForgeInvalidate(void);   // v2.11.1: 列表变化时强制重建
long mfReceiptForgeHits(void);
BOOL mfReceiptForgeIsOn(void);
void mfObjCHookToggle(UISwitch *sw);
void mfObjCHookEditTappedFromView(UIView *row);   // v2.6.79 点 cell 编辑
void mfObjCHookSwipeDelFromView(UIView *row);     // v2.6.79 左滑删除
void mfCloudKitWarmupStart(void);                 // v2.6.85 CK once 启动预热
BOOL mfCloudKitWarmReady(void);
void mfShowSelectorLocatorPage(void);      // v2.6.71 方法定位器页
void mfRunSelectorLocatorFromButton(UIButton *btn);
void mfShowDefaultsBrowserPage(void);      // v2.6.76 Defaults 浏览器
NSArray *mfFindClassesForSelector(NSString *selName);
void mfObjCHookDelTapped(UIButton *btn);
void mfObjCHookPersist(NSString *cls, NSString *sel, int mode, id val);

// ====== 网络分析（MFNetAnalyzer.m） ======
void mfShowNetAnalyzerPage(void);           // 网络功能统一入口（含捕获开关）
BOOL mfCaptureEnabledState(void);           // 定义在 MFNetworkCapture.m
NSArray *mfCapturedRecordsSnapshot(void);   // 捕获缓冲只读快照，同上
NSDictionary *mfReconFingerprint(void);     // v2.47.0 内购模式一次性侦查(扫描时点指纹)
UIView *mfReconMakeCard(NSDictionary *recon); // 置顶侦查卡(扫描页)
void mfReconApplySKResult(NSDictionary *recon, UIView *page, NSString *topPid, BOOL isLifetime); // SK 后回填第三类判定
void mfShowRuleManagerPage(void);           // 规则管理（拦截/改包）

