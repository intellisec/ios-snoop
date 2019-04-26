#import "Broker.h"
#import "NSDistributedNotificationCenter.h"
#import "AAClientLib.h"
#import "AAPilotNotification.h"

#define LOG

// The broker class is responsible for caching analysis results and for transmitting them to the backend
@implementation Broker : NSObject

- (void) saveReadPath:(NSString*) path {
    @synchronized(self.reads) {
        if (![self.reads containsObject:path]) {
#ifdef LOG
	NSLog(@"Read Path: %@", path);
#endif
            [self.reads addObject:path];
        }
    }
}

- (void) saveSyscall:(NSString*) syscall withParams:(NSString*) params {
	NSString *call = [NSString stringWithFormat:@"%@: %@", syscall, params];
    @synchronized(self.syscalls) {
#ifdef LOG
	NSLog(@"Syscall: %@(%@)", syscall, params);
#endif
        if (![self.syscalls containsObject:call]) {
            [self.syscalls addObject:call];
        }
    }
}

- (void) saveSuspiciousPath:(NSString*) path {
    @synchronized(self.suspicious) {
        if (!([self.writes containsObject:path] || [self.suspicious containsObject:path])) {
#ifdef SUSLOG
  NSLog(@"Suspicious: %@", path);
#endif
            [self.suspicious addObject:path];
        }
    }
}

- (void) saveAttributesPath:(NSString*) path {
    @synchronized(self.attributes) {
        if (![self.attributes containsObject:path]) {
#ifdef LOG
	NSLog(@"Attriutes: %@", path);
#endif
            [self.attributes addObject:path];
        }
    }
}

- (void) saveWritePath:(NSString*) path {
    @synchronized(self.writes) {
        if (![self.writes containsObject:path]) {
#ifdef LOG
	NSLog(@"Write Path: %@", path);
#endif
            [self.writes addObject:path];
        }
    }
}

- (void) saveURL:(NSURL*) url {
    @synchronized(self.urls) {
        if (![self.urls containsObject:url]) {
#ifdef LOG
	NSLog(@"URL: %@", url);
#endif
            [self.urls addObject:url];
        }
    }
}

- (void) sendResults {
	AAClientLib* client = [AAClientLib sharedInstance];
	NSDictionary* taskInfo = client.taskInfo;

	if (taskInfo != nil && [taskInfo objectForKey:@"bundleId"] != nil) {
        if ([[taskInfo objectForKey:@"bundleId"] isEqualToString:[[NSBundle mainBundle] bundleIdentifier]]) {

        	NSLog(@"Delivering results for %@ to DiOS backend", [[NSBundle mainBundle] bundleIdentifier]);

        	[client saveResult:@"YES" withType:@"run analysis"];

            @synchronized(self.reads) {
                if(self.reads != nil) {
                    if([self.reads count]>0) {
                        [client saveResult:self.reads withType:@"read_paths"];
                    }
                }
            }

            @synchronized(self.syscalls) {
                if(self.syscalls != nil) {
                    if([self.syscalls count]>0) {
                        [client saveResult:self.syscalls withType:@"syscalls"];
                    }
                }
            }

            @synchronized(self.attributes) {
                if(self.attributes != nil) {
                    if([self.attributes count]>0) {
                        [client saveResult:self.attributes withType:@"attributes"];
                    }
                }
            }

            @synchronized(self.writes) {
                if(self.writes != nil) {
                    if([self.writes count]>0) {
                        [client saveResult:self.writes withType:@"write_paths"];
                    }
                }
            }

            @synchronized(self.urls) {
                if(self.urls != nil) {
                    if([self.urls count]>0) {
                        [client saveResult:self.urls withType:@"urls"];
                    }
                }
            }

            @synchronized(self.suspicious) {
                if(self.suspicious != nil) {
                    if([self.suspicious count]>0) {
                        [client saveResult:self.suspicious withType:@"suspicious"];
                    }
                }
            }

        }
    }

}

- (void) registerExitHook {
	 [[NSDistributedNotificationCenter defaultCenter] addObserver:self selector:@selector(sendResults) name:AAPilotAppExecutionFinished object:nil];
     self.enabled = YES;
}

- (id) init {
    self = [super init];

    if (self) {
		self.reads = [[NSMutableArray alloc] init];
		self.writes = [[NSMutableArray alloc] init];
		self.attributes = [[NSMutableArray alloc] init];
		self.syscalls = [[NSMutableArray alloc] init];
		self.urls = [[NSMutableArray alloc] init];
		self.suspicious = [[NSMutableArray alloc] init];
    }

    return self;
}

+ (Broker*) sharedInstance {
	static Broker* sharedSingleton;

    @synchronized(self) {
        if (!sharedSingleton) {
            sharedSingleton = [[Broker alloc] init];
        }

        return sharedSingleton;
    }
}

@end
