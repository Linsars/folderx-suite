// LSApplicationProxy.h - Private headers from MobileCoreServices
// Generated via class-dump / ipsw analysis

#import <Foundation/Foundation.h>

@interface LSApplicationProxy : NSObject

// Basic properties
@property (readonly, copy) NSString *applicationIdentifier;      // Bundle ID
@property (readonly, copy) NSString *bundlePath;                  // Path to .app
@property (readonly, copy) NSString *dataPath;                    // Data container path
@property (readonly, copy) NSString *bundleVersion;               // CFBundleVersion
@property (readonly, copy) NSString *bundleShortVersionString;    // CFBundleShortVersionString
@property (readonly, copy) NSString *localizedName;               // Display name
@property (readonly) BOOL isSystemApplication;
@property (readonly) BOOL isPlaceholder;

// Entitlements
@property (readonly, copy) NSDictionary *embeddedEntitlements;    // Parsed entitlements dict
@property (readonly, copy) NSData *embeddedDerEntitlements;       // Raw DER entitlements

// Other useful properties
@property (readonly, copy) NSString *teamIdentifier;
@property (readonly, copy) NSDictionary *allEntitlements;         // May include more

@end

@interface LSApplicationWorkspace : NSObject

+ (instancetype)defaultWorkspace;
- (NSArray<LSApplicationProxy *> *)allApplications;
- (LSApplicationProxy *)applicationProxyForIdentifier:(NSString *)bundleID;
- (LSApplicationProxy *)applicationProxyForPath:(NSString *)path;

@end