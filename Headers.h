#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <MobileCoreServices/MobileCoreServices.h>
#import <spawn.h>

#define kRWSettingsPath @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"

@interface NSUserDefaults (FolderX)
- (id)objectForKey:(NSString *)key inDomain:(NSString *)domain;
- (void)setObject:(id)value forKey:(NSString *)key inDomain:(NSString *)domain;
@end

@interface SBFolderBackgroundView : UIView <UIColorPickerViewControllerDelegate>
+ (double)cornerRadiusToInsetContent;
+ (CGSize)folderBackgroundSize;
@end

@interface SBFloatyFolderView : UIView <UIColorPickerViewControllerDelegate>
- (void)_handleOutsideTap:(id)arg1;
- (CGFloat)folderSize;
@end

@interface SBFolderIconImageView : UIView <UIColorPickerViewControllerDelegate>
@property (nonatomic, retain) UIView *backgroundView;
@end

@interface SBHIconManager : NSObject
- (void)closeFolderAnimated:(BOOL)arg1 withCompletion:(id)arg2;
@end

@interface SBIconListView : UIView
- (unsigned long long)maximumIconCount;
@end

@interface SBFolder : NSObject
@property(copy, nonatomic) NSString *displayName;
- (NSArray *)icons;
- (id)allIcons;
@end

@interface SBFolderController : UIViewController
- (BOOL)isOpen;
@end

@interface SBIconController : UIViewController
@property (nonatomic,readonly) SBFolderController *currentFolderController;
@property (nonatomic,readonly) SBFolderController *openFolderController;
@property (nonatomic,readonly) SBHIconManager *iconManager;
+ (id)sharedInstance;
- (SBFolderController *)_openFolderController;
- (void)iconManager:(id)arg1 launchIconForIconView:(id)arg2;
- (void)iconManager:(SBHIconManager *)arg1 willCloseFolderController:(SBFolderController *)arg2;
@end

@class SBIconListView;

@interface SBIconView : UIView <UIColorPickerViewControllerDelegate>
@property (nonatomic, strong) SBIconListView *_atriaLastIconListView;
@property (nonatomic, strong) NSString *location;
- (id)_legibilitySettingsWithPrimaryColor:(UIColor *)color;
@end

@interface SBDockIconListView : SBIconListView
@end

@interface SBIconListGridLayoutConfiguration : NSObject
@property (nonatomic, readonly) unsigned long long numberOfPortraitRows;
@property (nonatomic, readonly) unsigned long long numberOfPortraitColumns;
@property (nonatomic, readonly) unsigned long long numberOfLandscapeRows;
@end

@interface _SBIconGridWrapperView : UIView
@property (nonatomic, assign) CGAffineTransform transform;
@end

@class UITextField, UIFont;
@interface SBFolderTitleTextField : UITextField
- (void)layoutSubviews;
@end

@interface _UIBackdropView : UIView
- (id)initWithStyle:(int)arg1;
@end

@interface SBHLibraryAdditionalItemsIndicatorIconImageView : SBFolderIconImageView
@property (nonatomic, assign) CGAffineTransform transform;
- (unsigned long long)concreteBackgroundStyle;
@end
