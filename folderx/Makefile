export ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = FolderX

FolderX_FILES = $(wildcard *.m)
FolderX_FRAMEWORKS = UIKit Security
FolderX_PRIVATE_FRAMEWORKS = Preferences CoreServices
FolderX_INSTALL_PATH = /Library/PreferenceBundles
FolderX_CFLAGS = -fobjc-arc -Wdeprecated-declarations -Wno-deprecated-declarations

include $(THEOS_MAKE_PATH)/bundle.mk
