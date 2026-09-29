#!/usr/bin/env python3
# 2.58.202: ① 引擎 recipe.dom 页面操作能力(killclick/clickjs/js — 杀模板跳转+调页面函数, 数据驱动)
#           ② 判定点页「＋手动 webinj@」入口(页面门非JSON可判, 人工贴recipe入库)
#           ③ dom 透传/行显/编辑文案
import sys

EDITS = [
    # ===== 引擎 JS: dom 操作(ls 块后插入) =====
    ("MFWebBridgeForge.m",
     '''    @"try{for(var i=0;i<R.length;i++){var lr=R[i];if(lr.ls){for(var lk in lr.ls){try{localStorage.setItem(lk,''+lr.ls[lk]);}catch(e){}}}}}catch(e){}"''',
     '''    @"try{for(var i=0;i<R.length;i++){var lr=R[i];if(lr.ls){for(var lk in lr.ls){try{localStorage.setItem(lk,''+lr.ls[lk]);}catch(e){}}}}}catch(e){}"
    @"try{for(var i=0;i<R.length;i++){var dr=R[i];if(!dr.dom||(''+location.href).indexOf(dr.u)<0)continue;for(var j=0;j<dr.dom.length;j++){var op=dr.dom[j];if(!op||!op.k)continue;"
    @"if(op.sel&&(op.k=='killclick'||op.k=='clickjs')){(function(s,v,kk){document.addEventListener('click',function(ev){try{var t=ev.target;while(t&&t.nodeType==1){if(t.matches&&t.matches(s)){ev.preventDefault();ev.stopPropagation();if(ev.stopImmediatePropagation)ev.stopImmediatePropagation();if(kk&&v){try{(0,eval)(v);}catch(e){}}return;}t=t.parentNode;}}catch(e){}},true);})(op.sel,op.v||'',op.k=='clickjs');}"
    @"else if(op.k=='js'&&op.v){try{document.addEventListener('DOMContentLoaded',function(){try{(0,eval)(op.v);}catch(e){}},{once:true});}catch(e){}}}}}catch(e){}"'''),
    # ===== recipe 透传 dom =====
    ("MFAppPatch.m",
     '''        if ([rc[@"bridge"] boolValue]) r[@"bridge"] = @YES;   // v2.58.200: 腿A 桥改写点位(webinj@bridge)
        if (r[@"set"] || r[@"req"] || r[@"ls"] || r[@"bridge"]) [out addObject:r];''',
     '''        if ([rc[@"bridge"] boolValue]) r[@"bridge"] = @YES;   // v258.200: 腿A 桥改写点位(webinj@bridge)
        if ([rc[@"dom"] isKindOfClass:[NSArray class]] && [rc[@"dom"] count]) r[@"dom"] = rc[@"dom"];   // v2.58.202: 页面操作(killclick/clickjs/js)
        if (r[@"set"] || r[@"req"] || r[@"ls"] || r[@"bridge"] || r[@"dom"]) [out addObject:r];'''),
    # ===== 行显: dom 点 tag =====
    ("MFAppPatch.m",
     '''        BOOL hasReq = [rc[@"req"] isKindOfClass:[NSDictionary class]];
        NSString *tag = hasReq ? @"改响应+匿名请求" : @"改响应";''',
     '''        BOOL hasReq = [rc[@"req"] isKindOfClass:[NSDictionary class]];
        BOOL hasDom = [rc[@"dom"] isKindOfClass:[NSArray class]] && [rc[@"dom"] count];
        NSString *tag = hasReq ? @"改响应+匿名请求" : @"改响应";
        if (hasDom) tag = (nset || hasReq) ? [tag stringByAppendingString:@"+dom"] : @"页面操作(dom)";'''),
    # ===== 编辑帮助文案 += dom =====
    ("MFAppPatch.m",
     '''                 @"整条规则 JSON:\\nset=改响应字段(点路径) · req.stripKeys=请求抹参数 · ls=localStorage",''',
     '''                 @"整条规则 JSON:\\nset=改响应 · req.stripKeys=抹参数 · ls=localStorage · dom=[{k:killclick|clickjs|js, sel, v}]",'''),
    # ===== 判定点页: shapeFilter 前移 + ＋手动按钮 + 空表标签下移 =====
    ("MFAppPatch.m",
     '''    UIView *page = mfMakePage(@"🎯 判定点", YES);
    g_apEntList = [[MFAPEntList alloc] init];
    // v2.58.61: UI 只读持久层(用户定案: 侦查→入库→卡片按类型显示, 会话缓存概念废除)
    NSArray *rawItems = mfAppPatchEntDumps();
    if (!rawItems.count) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 60, g_mfCardW - 32, 60)];''',
     '''    UIView *page = mfMakePage(@"🎯 判定点", YES);
    g_apEntList = [[MFAPEntList alloc] init];
    NSString *shapeFilter = objc_getAssociatedObject(self, "mfAPShapeFilter");
    // v2.58.202: 手动 webinj@ 入口 — 页面门/向导类规则(服务端模板硬编码跳转)无法从 JSON 采集自动
    //   判出(config_domain 案), 分析页面样本(page_*.html)后由用户贴 recipe 入库。数据在 recipe,
    //   引擎(dom 操作)通用零单靶硬编码。SK2 过滤视图不显。
    if (!shapeFilter.length) {
        UIButton *ba = [UIButton buttonWithType:UIButtonTypeSystem];
        ba.frame = CGRectMake(12, 46, g_mfCardW - 24, 34);
        ba.backgroundColor = [UIColor systemIndigoColor];
        ba.layer.cornerRadius = 8;
        ba.titleLabel.font = [UIFont systemFontOfSize:12.5 weight:UIFontWeightMedium];
        [ba setTitle:@"＋ 手动 webinj@ 规则(贴 recipe JSON)" forState:UIControlStateNormal];
        [ba setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
        [ba addTarget:g_mfCtrl action:@selector(mfAPAddWebinjManual) forControlEvents:UIControlEventTouchUpInside];
        [page addSubview:ba];
    }
    // v2.58.61: UI 只读持久层(用户定案: 侦查→入库→卡片按类型显示, 会话缓存概念废除)
    NSArray *rawItems = mfAppPatchEntDumps();
    if (!rawItems.count) {
        CGFloat ey = shapeFilter.length ? 60 : 88;
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, ey, g_mfCardW - 32, 60)];'''),
    # ===== 去掉后行重复的 shapeFilter 声明 =====
    ("MFAppPatch.m",
     '''    //   不再与 F8v2 fixups 点混排(用户: "判定点串行了? 两个卡片都是 17 个")
    NSString *shapeFilter = objc_getAssociatedObject(self, "mfAPShapeFilter");
    if (shapeFilter.length) {''',
     '''    //   不再与 F8v2 fixups 点混排(用户: "判定点串行了? 两个卡片都是 17 个")
    if (shapeFilter.length) {'''),
    # ===== 批量条下移(＋按钮占一行) =====
    ("MFAppPatch.m",
     '''        b1.frame = CGRectMake(12, 46, (g_mfCardW - 32) / 2, 34);''',
     '''        CGFloat by = shapeFilter.length ? 46 : 84;   // v2.58.202: 上方多「＋手动 webinj@」行
        b1.frame = CGRectMake(12, by, (g_mfCardW - 32) / 2, 34);'''),
    ("MFAppPatch.m",
     '''        b2.frame = CGRectMake(12 + (g_mfCardW - 32) / 2 + 8, 46, (g_mfCardW - 32) / 2, 34);''',
     '''        b2.frame = CGRectMake(12 + (g_mfCardW - 32) / 2 + 8, by, (g_mfCardW - 32) / 2, 34);'''),
    ("MFAppPatch.m",
     '''        batchH = 40;''',
     '''        batchH = shapeFilter.length ? 40 : 78;'''),
    # ===== 类目声明 =====
    ("MFAppPatch.m",
     '''- (void)mfAPRestoreTombstones:(UIButton *)btn;   // v2.58.77: 清墓碑(误删真点的退路)''',
     '''- (void)mfAPRestoreTombstones:(UIButton *)btn;   // v2.58.77: 清墓碑(误删真点的退路)
- (void)mfAPAddWebinjManual;                    // v2.58.202: 手动 webinj@ recipe 创建(页面门贴 JSON)'''),
    # ===== 创建动作 =====
    ("MFAppPatch.m",
     '''- (void)mfAPShowEntDumps {''',
     '''// v2.58.202: 手动 webinj@ 创建 — 页面门(config_domain 硬跳转/向导被藏)非 JSON 响应可判, 人工分析
//   页面样本(page_*.html)后贴 recipe。数据全在 recipe, 引擎 dom 操作通用 — 零单靶硬编码。
- (void)mfAPAddWebinjManual {
    mfInputSheet(@"➕ 手动 webinj@ 规则",
                 @"整条 recipe JSON(必含 u=页面URL子串):\\nset=改响应 · req.stripKeys=抹参数 · ls=localStorage · dom=[{k:killclick|clickjs|js, sel:, v:}]",
                 @"{\\"u\\":\\"\\",\\"dom\\":[{\\"k\\":\\"clickjs\\",\\"sel\\":\\"#\\",\\"v\\":\\"\\"}]}", YES, ^(NSString *txt) {
        NSData *nd = [(txt ?: @"") dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *rc = nd ? [NSJSONSerialization JSONObjectWithData:nd options:0 error:nil] : nil;
        if (![rc isKindOfClass:[NSDictionary class]] || ![rc[@"u"] isKindOfClass:[NSString class]] || ![rc[@"u"] length]) {
            mfToast(@"⛔ 需含 u 字段的 JSON 对象"); return;
        }
        NSString *img = [[NSBundle mainBundle].executablePath lastPathComponent] ?: @"main";
        NSString *sym = [NSString stringWithFormat:@"webinj@manual%08x", arc4random_uniform(0xffffffffu)];
        NSDictionary *pt = @{ @"img": img, @"sym": sym, @"shape": @"webinj", @"kind": @"webforge",
            @"vmaddr": @0, @"slide": @0, @"score": @90, @"on": @NO,
            @"note": [NSString stringWithFormat:@"手动规则: %@", rc[@"u"]], @"recipe": rc };
        extern NSUInteger mfAppPatchEntDumpsMerge(NSArray *);
        if (!mfAppPatchEntDumpsMerge(@[pt])) { mfToast(@"⛔ 入库失败"); return; }
        mfToast(@"✅ 已入库(off) — 左划⚡激活后重启生效");
    });
}
- (void)mfAPShowEntDumps {'''),
]

applied = {}
for path, old, new in EDITS:
    src = open(path, encoding="utf-8").read()
    cnt = src.count(old)
    if cnt != 1:
        print(f"FAIL {path}: pattern count={cnt}\n---\n{old[:220]}")
        sys.exit(1)
    open(path, "w", encoding="utf-8").write(src.replace(old, new, 1))
    applied[path] = applied.get(path, 0) + 1
print("OK", applied)
