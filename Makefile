export ARCHS = arm64 arm64e
GO_EASY_ON_ME = 1

TARGET = iphone:clang:14.5
THEOS_LAYOUT_DIR_NAME = layout-rootless
THEOS_PACKAGE_SCHEME = rootless

export SYSROOT = $(THEOS)/sdks/iPhoneOS14.5.sdk

include $(THEOS)/makefiles/common.mk

# v2.5.0 按「注入目标」分类(真相源: ARCHITECTURE.md,架构变动必须同步更新它)
TWEAK_NAME = FolderX AppHooks IAPtools CompatPatcher

# FolderX(SpringBoard: 文件夹变色 + 系统增强[充电限制/Wi-Fi永连])
FolderX_FILES = $(filter-out MFChainA.m MFPanel.m MFNetworkCapture.m MFAppStoreSpoof.m MFTestFlightHooks.m MFKeychainManager.m MFClassDump.m MFDiagnostics.m MFNetAnalyzer.m MFCryptoToolbox.m MFCryptoHooks.m MFObjCHook.m MFHostLogCapture.m MFBatteryInfo.m MFDiagnosticCleaner.m MFSubInject.m MFReceiptForge.m MFReflixOracle.m MFAppPatch.m MFProcCapture.m MFRecon.m MFSKQueueForge.m, $(wildcard *.xm *.m *.mm))
FolderX_FRAMEWORKS = UIKit Foundation SpringBoardServices
FolderX_CFLAGS = -fno-objc-arc -fmodules
MFSystemEnhance.m_CFLAGS = -fobjc-arc
FolderX_ARCHS = arm64 arm64e
FolderX_INSTALL_PATH = /usr/lib/TweakInject

# SuiteTools(原 IAPtools, 内部代号保留——全局 UIKit 注入的工具组件)
IAPtools_FILES = MFChainA.m MFSKQueueForge.m MFRecon.m MFPanel.m MFNetworkCapture.m MFDiagnosticCleaner.m MFKeychainManager.m MFClassDump.m MFDiagnostics.m MFNetAnalyzer.m MFCryptoToolbox.m MFCryptoHooks.m MFObjCHook.m MFHostLogCapture.m MFBatteryInfo.m MFSubInject.m MFReceiptForge.m MFReflixOracle.m MFProcCapture.m MFAppPatch.m fishhook.c
IAPtools_FRAMEWORKS = UIKit Foundation Security
IAPtools_LDFLAGS = -weak_framework UIKit -weak_framework StoreKit -weak_framework JavaScriptCore -lz
IAPtools_CFLAGS = -fobjc-arc -Wno-everything -DMF_BUILD_VER_S='"2.59.3"'
IAPtools_ARCHS = arm64 arm64e
IAPtools_INSTALL_PATH = /usr/lib/TweakInject

# v2.46.1: ReflixStub 判决件退役(存在性假说已被内联补丁终结) — 死文件清理

# AppHooks v2.4.0(原 AppStoreSpoof 扩编——指定进程注入: appstored/installd/TestFlight)
AppHooks_FILES = MFAppStoreSpoof.m MFTestFlightHooks.m
AppHooks_FRAMEWORKS = Foundation
AppHooks_CFLAGS = -fobjc-arc
AppHooks_ARCHS = arm64 arm64e
AppHooks_INSTALL_PATH = /usr/lib/TweakInject

# CompatPatcher v2.7.3(全局 UIKit: iOS 18+ SDK app 运行时 GOT 修复——符号池 1 刀等价,零重签)
CompatPatcher_FILES = MFCompatPatcher.m
CompatPatcher_FRAMEWORKS = Foundation
CompatPatcher_CFLAGS = -fobjc-arc
CompatPatcher_ARCHS = arm64 arm64e
CompatPatcher_INSTALL_PATH = /usr/lib/TweakInject


include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += folderx
include $(THEOS_MAKE_PATH)/aggregate.mk
