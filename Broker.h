#import <Foundation/Foundation.h>

@interface Broker : NSObject

- (void) saveReadPath:(NSString*) path;
- (void) saveSyscall:(NSString*) syscall withParams:(NSString*) params;
- (void) saveSuspiciousPath:(NSString*) path;
- (void) saveAttributesPath:(NSString*) path;
- (void) saveWritePath:(NSString*) path;
- (void) saveURL:(NSURL*) url;
- (void) sendResults;
- (void) registerExitHook;

+ (Broker*) sharedInstance;

@property BOOL enabled;
@property (strong, nonatomic) NSMutableArray *reads;
@property (strong, nonatomic) NSMutableArray *writes;
@property (strong, nonatomic) NSMutableArray *attributes;
@property (strong, nonatomic) NSMutableArray *syscalls;
@property (strong, nonatomic) NSMutableArray *urls;
@property (strong, nonatomic) NSMutableArray *suspicious;

@end
