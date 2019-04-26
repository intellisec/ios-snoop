#import <sys/stat.h>
#import <sys/types.h>
#import <mach-o/dyld.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdarg.h>
#include <objc/runtime.h>

#import <AVFoundation/AVFoundation.h>

#import "UIKeyboardImpl.h"
#import "DOMHTMLInputElement.h"
#import "UIThreadSafeNode.h"
#import "UIWebTouchEventsGestureRecognizer.h"

#import "Broker.h"
#import "AAClientLib.h"

#define ObjAsKey(obj) [NSValue valueWithNonretainedObject:obj]


typedef NSString *NSFileAttributeKey;

NSString *appFolderPath;
NSString *documentDirectory;

// ignore call if it is triggered from some other hook
BOOL objcCall = NO;

BOOL disabled = NO;

NSArray* jailbreakFiles = [NSArray arrayWithObjects:
		@"/bin/bash",
		@"/bin/sh",
		@"/etc/apt",
		@"/etc/ssh/sshd_config",
		@"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
		@"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
		@"/Library/MobileSubstrate/MobileSubstrate.dylib",
		@"/panguaxe",
		@"/panguaxe.installed",
		@"/private/var/lib/apt",
		@"/private/var/lib/cydia",
		@"/private/var/lib/dpkg/info/io.pangu.axe7.list",
		@"/private/var/lib/dpkg/info/io.pangu.axe7.prerm",
		@"/private/var/mobile/Library/SBSettings/Themes",
		@"/private/var/mobile/Media/panguaxe.installed",
		@"/private/var/stash",
		@"/private/var/tmp/cydia.log",
		@"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
		@"/System/Library/LaunchDaemons/io.pangu.axe.untether.plist",
		@"/usr/bin/sshd",
		@"/usr/libexec/sftp-server",
		@"/usr/libexec/ssh-keysign",
		@"/usr/bin/ssh",
		@"/usr/sbin/sshd",
		@"/var/cache/apt",
		@"/var/lib/apt",
		@"/var/lib/cdia",
		@"/var/log/syslog",
		@"/etc/clutch.conf",
		@"/var/cache/clutch.plist",
		@"/etc/clutch_cracked.plist",
		@"/var/cache/clutch_cracked.plist",
		@"/var/lib/clutch/overdrive.dylib",
		@"/var/root/Documents/Cracked",
		@"/var/mobile/Library/PPTDevice",
		@"/System/Library/LaunchDaemons/com.evad3rs.evasi0n7.untether.plist",
		@"/System/Library/LaunchDaemons/io.pangu.untether.plist",
		@"/evasi0n7",
		@"/pguntether",
		@"/var/stash/Library/Ringtones",
		@"/var/stash/Library/Wallpaper",
		@"/var/stash/usr/include",
		@"/var/stash/usr/libexec",
		@"/var/stash/usr/share",
		@"/var/stash/usr/arm-apple-darwin9",
		@"/private/var/lib/dpkg/info/taiguntether83x.extrainst_",
		@"/private/var/lib/dpkg/info/taiguntether83x.list",
		@"/private/var/lib/dpkg/info/taiguntether83x.preinst",
		@"/private/var/lib/dpkg/info/taiguntether83x.prerm",
		@"/usr/bin/ldid",
		@"/usr/bin/plutil",
		@"/usr/bin/codesign_allocate",
		@"/bin/gzip",
		@"/bin/tar",
		@"/bin/mv",
		@"/bin/gunzip",
		@"/bin/cp",
		@"/taig/",
		@"/taig/taig",
		@"/private/var/lib/dpkg/info/io.pangu.fuxiqin9.list",
		@"/private/var/lib/dpkg/info/io.pangu.fuxiqin9.prerm",
		nil];
NSArray* jailbreakApps = [NSArray arrayWithObjects:
		@"/Applications/blackra1n.app",
		@"/Applications/Cydia.app",
		@"/Applications/FakeCarrier.app",
		@"/Applications/Icy.app",
		@"/Applications/IntelliScreen.app",
		@"/Applications/MxTube.app",
		@"/Applications/RockApp.app",
		@"/Applications/SBSettings.app",
		@"/Applications/Snoop-it Config.app",
		@"/Applications/WinterBoard.app",
		@"/Applications/limera1n.app",
		@"/Applications/greenpois0n.app",
		@"/Applications/blacksn0w.app",
		@"/Applications/redsn0w.app",
		nil];
NSArray* shouldNotBeSymbolicLink = [NSArray arrayWithObjects:
		@"/Applications",
		@"/Library/Ringtones",
		@"/Library/Wallpaper",
		@"/usr/arm-apple-darwin9",
		@"/usr/include",
		@"/usr/libexec",
		@"/usr/share",
		nil];
NSArray* specialLinks = [NSArray arrayWithObjects:
		@"/var/stash/Library/Ringtones",
		@"/var/stash/Library/Wallpaper",
		@"/var/stash/usr/include",
		@"/var/stash/usr/libexec",
		@"/var/stash/usr/share",
		@"/var/stash/usr/arm-apple-darwin9",
		nil];
NSArray* unwritableFiles = [NSArray arrayWithObjects:
		@"/ect/groups",
		@"/etc/passwd",
		nil];
NSArray* nonWritablePathes = [NSArray arrayWithObjects:
		@"/private",
		@"/private/var/mobile/Applications",
		@"/private/var/mobile/Containers",
		nil];

//paths to ignore
NSArray* nonSuspiciousPathes = [NSArray arrayWithObjects:
		@"/var/mobile/Library/Caches/com.apple.UIStatusBar/version",
		@"/var/mobile/Library/ConfigurationProfiles/PublicInfo/MCMeta.plist",
		@"Celestial",
		nil];
NSArray* nonSuspiciousDirectories = [NSArray arrayWithObjects:
		@"/System/Library/PrivateFrameworks/",
		@"/Applications/Reminders.app",
		@"/Applications/SocialUIService.app",
		@"/Applications/MobileNotes.app",
		@"/Applications/Music.app",
		nil];

/*
 * Disguise jailbreak typical files
 */
%hookf(FILE *, fopen, const char *path, const char *mode) {
	if (disabled) {
		return %orig;
	}

	NSString *string = [NSString stringWithCString:path
                                   encoding:[NSString defaultCStringEncoding]];
    NSString *modus = [NSString stringWithCString:mode
                                   encoding:[NSString defaultCStringEncoding]];

	if (([unwritableFiles containsObject: string] && ![modus isEqualToString:@"r"])
			|| [jailbreakFiles containsObject: string]
			|| [jailbreakApps containsObject: string]) {

		[[Broker sharedInstance] saveSyscall:@"fopen" withParams:string];
		errno = ENOENT;
		return %orig("/no/jailbreak", mode);
	}

	return %orig;
}

/*
 * Replace compromising image names with random strings
 *
 * No logging because of stability problems with some apps
 */
%hookf(const char*, _dyld_get_image_name, uint32_t image_index) {
	if (disabled) {
		return %orig;
	}

	const char* ret = %orig;
	NSString *name = [NSString stringWithCString:ret
                                   encoding:[NSString defaultCStringEncoding]];

	if ([name rangeOfString:@"MobileSubstrate"].location != NSNotFound
			|| [name rangeOfString:@"Cydia"].location != NSNotFound
			|| [name rangeOfString:@"cydia"].location != NSNotFound
			|| [name rangeOfString:@"SBSettings"].location != NSNotFound
			|| [name rangeOfString:@"WinterBoard"].location != NSNotFound
			|| [name rangeOfString:@"xCon"].location != NSNotFound
			|| [name rangeOfString:@"tsProtector"].location != NSNotFound) {

		NSString *letters = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		NSMutableString *randomString = [NSMutableString stringWithCapacity: 20];
		for (int i=0; i < 20; i++) {
			[randomString appendFormat: @"%C", [letters characterAtIndex: arc4random_uniform([letters length])]];
		}

		ret = [randomString UTF8String];
		//[[Broker sharedInstance] saveSyscall:@"_dyld_get_image_name" withParams:name];
	}
	return ret;
}

%hookf(int, lstat, const char *path, struct stat *buffer) {
	if (disabled) {
		return %orig;
	}
	if (objcCall) {
		return %orig;
	}

	NSString *pathString = [NSString stringWithCString:path
                                   encoding:[NSString defaultCStringEncoding]];

	if ([shouldNotBeSymbolicLink containsObject: pathString] ||
		[specialLinks containsObject: pathString]) {

  		[[Broker sharedInstance] saveSyscall:@"lstat" withParams:pathString];
		if (%orig > -1 || [specialLinks containsObject: pathString]) {
			int newMode = ((buffer->st_mode | S_IFLNK) ^ S_IFLNK) | S_IFDIR;
			buffer->st_mode = newMode;
			return 0;
		}

		return %orig;
	}

	if ([jailbreakFiles containsObject: pathString]
			|| [jailbreakApps containsObject: pathString]
			|| [pathString rangeOfString:@"cydia"].location != NSNotFound
			|| [pathString rangeOfString:@"Cydia"].location != NSNotFound
			|| [pathString rangeOfString:@"SBSettings"].location != NSNotFound
			|| [pathString rangeOfString:@"MobileSubstrate"].location != NSNotFound) {

		if ([[[NSThread callStackSymbols] lastObject] rangeOfString:@"libdyld.dylib"].location == NSNotFound) {
			[[Broker sharedInstance] saveSyscall:@"lstat" withParams:pathString];
		}
		const char *newPath = "/no/jailbreak";
		return %orig(newPath, buffer);;
	}

	return %orig;
}

%hookf(int, stat, const char *path, struct stat *buffer) {
	if (disabled) {
		return %orig;
	}
	if (objcCall) {
		return %orig;
	}

	NSString *string = [NSString stringWithCString:path
                                   encoding:[NSString defaultCStringEncoding]];
	
	if ([shouldNotBeSymbolicLink containsObject: string] ||
		[specialLinks containsObject: string]) {

  		[[Broker sharedInstance] saveSyscall:@"stat" withParams:string];
		if (%orig > -1 || [specialLinks containsObject: string]) {
			int newMode = ((buffer->st_mode | S_IFLNK) ^ S_IFLNK) | S_IFDIR;
			buffer->st_mode = newMode;
			return 0;
		}

		return %orig;
	}

	if ([jailbreakFiles containsObject: string]
			|| [jailbreakApps containsObject: string]
			|| [string rangeOfString:@"cydia"].location != NSNotFound
			|| [string rangeOfString:@"Cydia"].location != NSNotFound
			|| [string rangeOfString:@"SBSettings"].location != NSNotFound
			|| [string rangeOfString:@"MobileSubstrate"].location != NSNotFound) {

		[[Broker sharedInstance] saveSyscall:@"stat" withParams:string];
		const char *newPath = "/no/jailbreak";
		return %orig(newPath, buffer);
	}

	return %orig;
}


/*
 * Block fork
 */
%hookf(pid_t, fork) {
	if (disabled) {
		return %orig;
	}

	[[Broker sharedInstance] saveSyscall:@"fork" withParams:@""];
	return -1;
}

/*
 * Imitate system(NULL)
 */
%hookf(int, system, const char *command) {
	if (disabled) {
		return %orig;
	}
	if (command) {
    	return %orig;
    }

	[[Broker sharedInstance] saveSyscall:@"system" withParams:@"NULL"];

	return 0;
}

/*
 * Logging inputs
 */

// Contains usual listener for Textviews if present
NSMutableDictionary *textFields = [[NSMutableDictionary alloc] init];

// Contains all input texts with some additional informations (if possible)
NSMutableDictionary *textInputs = [[NSMutableDictionary alloc] init];

%hook UITextField

/*
 * If not our listener will be added, we store the listener in textFields for later use
 */
- (void)addTarget:(id)target action:(SEL)selector forControlEvents:(unsigned long long)events {
	if (![target isEqual:self] && selector != @selector(textFieldDidChange:)) {
		NSInvocation *invocation = 
							[NSInvocation invocationWithMethodSignature:[target methodSignatureForSelector:selector]];
		invocation.selector = selector;
		invocation.target = target;
		[textFields setObject:invocation forKey:ObjAsKey(self)];
		[self addTarget:self action:@selector(textFieldDidChange:) forControlEvents:events];
	} else {
		%orig;
	}
}

/*
 * Add our listener to all UITextFields when creating
 */
- (id)initWithCoder:(id)arg1 {
	id ret = %orig;
	[ret addTarget:self action:@selector(textFieldDidChange:) 
		forControlEvents:UIControlEventEditingDidEnd | UIControlEventEditingDidEndOnExit];
	return ret;
}
- (id)initWithFrame:(CGRect)arg1 {
	id ret = %orig;
	[ret addTarget:self action:@selector(textFieldDidChange:) 
		forControlEvents:UIControlEventEditingDidEnd | UIControlEventEditingDidEndOnExit];
	return ret;
}

%new
-(void)textFieldDidChange :(UITextField *) textField {
	//If there isn't a text-property, call the listener stored in textFields-dictionary
	if (![textField respondsToSelector:@selector(text)]) {
		NSInvocation *invocation = textFields[ObjAsKey(self)];
		if ([[invocation methodSignature] numberOfArguments] > 2) {
			[invocation setArgument:textField atIndex:2];
		}
		[invocation invoke];
		return;
	}
	//Get some additional informations to the input
	NSMutableArray *views = [[NSMutableArray alloc] init];
	NSDictionary *data = @{@"secureTextEntry":textField.secureTextEntry ? @"YES" : @"NO",
							   @"placeholder":textField.placeholder ? textField.placeholder : @"",
									  @"text":textField.text ? textField.text : @"",
									 @"views":views};
	//We use the view as identifier for all fields (and for structuring)
	UIView *highestView = textField;
	while (highestView.superview) {
		highestView = highestView.superview;
	}
	if (![textInputs objectForKey:ObjAsKey(highestView)]) {
		textInputs[ObjAsKey(highestView)] = [[NSMutableDictionary alloc] init];
	}

	textInputs[ObjAsKey(highestView)][ObjAsKey(textField)] = data;

	// Get surrounding views for context
	for (UIView *view in textField.superview.subviews) {
		if ([view isKindOfClass:[UILabel class]]) {
			[views addObject:[NSString stringWithFormat:@"Label(%@): %@%@", 
															ObjAsKey(view), 
															((UILabel *) view).text, 
															view.hidden ? @" (hidden)" : @""]];
		} else if ([view isKindOfClass:[UITextView class]]) {
			[views addObject:[NSString stringWithFormat:@"TextView(%@): %@", 
															ObjAsKey(view), 
															((UITextView *) view).text]];
		} else if ([view isKindOfClass:[UITextField class]]) {
			[views addObject:[NSString stringWithFormat:@"TextField(%@): %@", 
															ObjAsKey(view), 
															((UITextField *) view).text]];
		}
	}

	// Call the listener stored in textFields-dictionary
	NSInvocation *invocation = textFields[ObjAsKey(self)];
	if ([[invocation methodSignature] numberOfArguments] > 2) {
		[invocation setArgument:textField atIndex:2];
	}
	[invocation invoke];

	// For now, display inputs in syslog, also possible to send them to a server
	NSLog(@"Dict:\n%@", textInputs);
}

%end

%hook NSFileManager

/*
 * Hide existence of typical apps and files
 */
-(BOOL)fileExistsAtPath:(NSString*)path {
	if (disabled) {
		return %orig;
	}
	if (path == nil) {
		return %orig;
	}

	if ([path hasPrefix:@"//"]) {
		path = [path substringFromIndex:1];
	}
	if ([path hasSuffix:@"/"]) {
		path = [path substringToIndex:[path length] - 1];
	}
	if ([jailbreakFiles containsObject: path]
			|| [jailbreakApps containsObject: path]
			|| [path rangeOfString:@"cydia"].location != NSNotFound
			|| [path rangeOfString:@"Cydia"].location != NSNotFound
			|| [path rangeOfString:@"SBSettings"].location != NSNotFound
			|| [path rangeOfString:@"MobileSubstrate"].location != NSNotFound) {

		[[Broker sharedInstance] saveReadPath:path];
		return NO;
	}
	/*
	 * Suspicious paths are not block, but they seem to be kind of interesting
	 * for evasion of improved detections. We log them for later analysis if needed.
	 */
	if (!([path hasPrefix:documentDirectory]
			|| [path hasPrefix:[NSString stringWithFormat:@"/private%@", documentDirectory]]
			|| [path hasPrefix:appFolderPath] || [nonSuspiciousPathes containsObject:path])) {

		BOOL save = YES;
		// Check if this path is part of another suspicious path
		for (int i = 0; i < [nonSuspiciousDirectories count]; i++) {
			if ([path hasPrefix:[nonSuspiciousDirectories objectAtIndex:i]]) {
				save = NO;
			}
		}
		if (save) {
			[[Broker sharedInstance] saveSuspiciousPath:path];
		}
	}

	return %orig;
}

-(BOOL)fileExistsAtPath:(NSString*)path isDirectory:(BOOL*)isDirectory {
	if (disabled) {
		return %orig;
	}
	if (path == nil) {
		return %orig;
	}

	if ([path hasPrefix:@"//"]) {
		path = [path substringFromIndex:1];
	}
	if ([path hasSuffix:@"/"]) {
		path = [path substringToIndex:[path length] - 1];
	}
	if ([jailbreakFiles containsObject: path]
			|| [jailbreakApps containsObject: path]
			|| [path rangeOfString:@"cydia"].location != NSNotFound
			|| [path rangeOfString:@"Cydia"].location != NSNotFound
			|| [path rangeOfString:@"SBSettings"].location != NSNotFound
			|| [path rangeOfString:@"MobileSubstrate"].location != NSNotFound) {

		[[Broker sharedInstance] saveReadPath:path];
		return NO;
	}
	if (!([path hasPrefix:documentDirectory]
			|| [path hasPrefix:[NSString stringWithFormat:@"/private%@", documentDirectory]]
			|| [path hasPrefix:appFolderPath] || [nonSuspiciousPathes containsObject:path])) {
		BOOL save = YES;
		for (int i = 0; i < [nonSuspiciousDirectories count]; i++) {
			if ([path hasPrefix:[nonSuspiciousDirectories objectAtIndex:i]]) {
				save = NO;
			}
		}
		if (save) {
			[[Broker sharedInstance] saveSuspiciousPath:path];
		}
	}

	return %orig;
}

/*
 * hide symbolic links and the creation and change date
 */
- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
	if (disabled) {
		return %orig;
	}
	objcCall = YES; // this method uses lstat, but we don't want to log this call
	NSDictionary<NSFileAttributeKey, id> * ret = %orig;
	objcCall = NO;

	if ([shouldNotBeSymbolicLink containsObject: path]) {
		[[Broker sharedInstance] saveAttributesPath:path];

		NSDictionary* dict = [NSDictionary dictionaryWithObjectsAndKeys:
			[ret objectForKey:NSFileSize], NSFileSize,
			[ret objectForKey:NSFilePosixPermissions], NSFilePosixPermissions,
			[ret objectForKey:NSFileReferenceCount], NSFileReferenceCount,
			[ret objectForKey:NSFileGroupOwnerAccountID], NSFileGroupOwnerAccountID,
			[ret objectForKey:NSFileOwnerAccountName], NSFileOwnerAccountName,
			NSFileTypeRegular, NSFileType, 													//change filetype to regular
			[ret objectForKey:NSFileSystemFileNumber], NSFileSystemFileNumber,
			[ret objectForKey:NSFileExtensionHidden], NSFileExtensionHidden,
			[NSDate dateWithTimeIntervalSince1970:1277155863], NSFileModificationDate, 		//modify change date 
			[ret objectForKey:NSFileGroupOwnerAccountName], NSFileGroupOwnerAccountName,
			[NSDate dateWithTimeIntervalSince1970:828274380], NSFileCreationDate, 			//modify creation date
			[ret objectForKey:NSFileSystemNumber], NSFileSystemNumber,
			[ret objectForKey:NSFileOwnerAccountID], NSFileOwnerAccountID,
			nil];

		return dict;
	}
	if (!([path hasPrefix:documentDirectory]
						|| [path hasPrefix:[NSString stringWithFormat:@"/private%@", documentDirectory]]
						|| [path hasPrefix:appFolderPath] || [nonSuspiciousPathes containsObject:path])) {

		BOOL save = YES;
		for (int i = 0; i < [nonSuspiciousDirectories count]; i++) {
			if ([path hasPrefix:[nonSuspiciousDirectories objectAtIndex:i]]) {
				save = NO;
			}
		}
		if (save) {
			[[Broker sharedInstance] saveSuspiciousPath:path];
		}
	}

	return ret;
}

%end

%hook NSString

/*
 * Control write accesses
 *
 * Modifying only the return value is not enough, also the error code has to be correct
 */
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile
			encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
	if (disabled) {
		return %orig;
	}

	NSDictionary* userInfo = [NSDictionary dictionaryWithObjectsAndKeys:
								path, @"NSFilePath",
								@"Error Domain=NSPOSIXErrorDomain Code=13 \"Permission denied\"", @"NSUnderlyingError",
								nil];
	NSError *myError = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:513 userInfo:userInfo];

	// Not only check the entire path, but also wether the prefix is a non writable path
	BOOL detection = NO;
	for (NSString *noWrite in nonWritablePathes) {
		if ([path hasPrefix:noWrite]) {
			detection = YES;
		}
	}
	if (detection || [path rangeOfString:@"jailbreak"].location != NSNotFound
				  || [path rangeOfString:@"Jailbreak"].location != NSNotFound) {

		[[Broker sharedInstance] saveWritePath:path];
		*error = myError;
		return NO;
	}
	if (!([path hasPrefix:documentDirectory]
						|| [path hasPrefix:[NSString stringWithFormat:@"/private%@", documentDirectory]]
						|| [path hasPrefix:appFolderPath]
						|| [nonSuspiciousPathes containsObject:path])) {

		BOOL save = YES;
		for (int i = 0; i < [nonSuspiciousDirectories count]; i++) {
			if ([path hasPrefix:[nonSuspiciousDirectories objectAtIndex:i]]) {
				save = NO;
			}
		}
		if (save) {
			[[Broker sharedInstance] saveSuspiciousPath:path];
		}
	}

	return %orig;
}

/*
 * Control write accesses
 *
 * Modifying only the return value is not enough, also the error code has to be correct
 */
- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)useAuxiliaryFile
			encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
	if (disabled) {
		return %orig;
	}

	NSString* path = [url path];

	NSDictionary* userInfo = [NSDictionary dictionaryWithObjectsAndKeys:
								path, @"NSFilePath",
								@"Error Domain=NSPOSIXErrorDomain Code=13 \"Permission denied\"", @"NSUnderlyingError",
								nil];
	NSError *myError = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:513 userInfo:userInfo];

	BOOL detection = NO;
	for (NSString *noWrite in nonWritablePathes) {
		if ([path hasPrefix:noWrite]) {
			detection = YES;
		}
	}
	if (detection || [path rangeOfString:@"jailbreak"].location != NSNotFound
				   || [path rangeOfString:@"Jailbreak"].location != NSNotFound) {
		[[Broker sharedInstance] saveWritePath:path];
		*error = myError;
		return NO;
	}

	if (!([path hasPrefix:documentDirectory]
						|| [path hasPrefix:[NSString stringWithFormat:@"/private%@", documentDirectory]]
						|| [path hasPrefix:appFolderPath]
						|| [nonSuspiciousPathes containsObject:path])) {

		BOOL save = YES;
		for (int i = 0; i < [nonSuspiciousDirectories count]; i++) {
			if ([path hasPrefix:[nonSuspiciousDirectories objectAtIndex:i]]) {
				save = NO;
			}
		}
		if (save) {
			[[Broker sharedInstance] saveSuspiciousPath:path];
		}
	}

	return %orig;
}

%end

%hook UIApplication

/*
 * Hide specific url-schema of cydia
 */
- (BOOL)canOpenURL:(NSURL *)url {
	if (disabled) {
		return %orig;
	}

	if ([[url scheme] isEqual:@"cydia"]) {
		[[Broker sharedInstance] saveURL:url];
		return NO;
	}
	return %orig;
}

%end

/*
 * Get Inputs in WebView
 */

NSMutableString *inputString = [[NSMutableString alloc] init];
NSMutableDictionary *inputDict = [[NSMutableDictionary alloc] init];
NSObject *inputField = nil;
NSString *focus = nil;

%hook UIKeyboardImpl

- (void)insertText:(NSString *)text {
	%log;
	NSObject *input = [self inputDelegate];
	NSDictionary *data = nil;
	if ([input isKindOfClass:NSClassFromString(@"UIThreadSafeNode")]) {
		NSLog(@"Test");
		DOMHTMLInputElement *realNode = [((UIThreadSafeNode *)input) _realNode];
		NSString *html = [[realNode parentElement] outerHTML];
		if ([[realNode parentElement] parentElement]) {
			html = [[[realNode parentElement] parentElement] outerHTML];
		}
		if ([[[realNode parentElement] parentElement] parentElement]) {
			html = [[[[realNode parentElement] parentElement] parentElement] outerHTML];
		}
		data = @{@"placeholder":realNode.placeholder ? realNode.placeholder : @"",
						@"name":realNode.name ? realNode.name : @"",
						 @"src":realNode.src ? realNode.src : @"",
						@"text":[[NSMutableString alloc] init],
					 	@"HTML":html};
		input = [((UIThreadSafeNode *)input) _realNode];
	} else if ([input isKindOfClass:NSClassFromString(@"UITextField")]) {
		NSLog(@"Test2");
		UITextField *realNode = (UITextField *) input;
		NSMutableArray *views = [[NSMutableArray alloc] init];
		data = @{@"secureTextEntry":realNode.secureTextEntry ? @"YES" : @"NO",
					 @"placeholder":realNode.placeholder ? realNode.placeholder : @"",
							@"text":[[NSMutableString alloc] init],
					 	   @"views":views};

	 	for (UIView *view in realNode.superview.subviews) {
			if ([view isKindOfClass:[UILabel class]]) {
				[views addObject:[NSString stringWithFormat:@"Label(%@): %@%@", 
															ObjAsKey(view), 
															((UILabel *) view).text, 
															view.hidden ? @" (hidden)" : @""]];
			} else if ([view isKindOfClass:[UITextView class]]) {
				[views addObject:[NSString stringWithFormat:@"TextView(%@): %@", 
															ObjAsKey(view), 
															((UITextView *) view).text]];
			} else if ([view isKindOfClass:[UITextField class]]) {
				[views addObject:[NSString stringWithFormat:@"TextField(%@): %@", 
															ObjAsKey(view), 
															((UITextField *) view).text]];
			}
		}
	}

	if (![inputDict objectForKey:ObjAsKey(input)] && data != nil) {
		inputDict[ObjAsKey(input)] = data;
		inputString = data[@"text"];
	}

	if (![input isEqual:inputField]) {
		inputField = input;
		inputString = inputDict[ObjAsKey(inputField)][@"text"];
	}

	if (inputString != nil) {
		[inputString appendString:text];
	}

	NSLog(@"%@", inputDict);
	%orig;
}

- (void)deleteBackward {
	%log;
	%orig;
	if (inputString == nil || [inputString length] == 0) {
		return;
	}
	[inputString replaceCharactersInRange:NSMakeRange([inputString length]-1,1) withString:@""];
}

-(void)deleteBackwardAndNotify:(BOOL)arg0 {
	%orig;
	if (inputString == nil || [inputString length] == 0) {
		return;
	}
	[inputString replaceCharactersInRange:NSMakeRange([inputString length]-1,1) withString:@""];
}

%end

/*
 * Hooks for custom keyboard in com.db.pbc.mibanco
 */

//Map for chars associated with the keys
id keyMap = nil;

%hook WebServiceCall

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
	NSError *error = nil;
	id object = [NSJSONSerialization
                    JSONObjectWithData:data
                    options:0
                    error:&error];

    if(!error && [object isKindOfClass:[NSDictionary class]]) {
        NSDictionary *results = object;
		keyMap = results[@"virtualKeyboardPosition"];
	}
	%orig;
}

%end

CGPoint last;

%hook UIWebBrowserView

-(void)_webTouchEventsRecognized:(id)arg1 {
	UIWebTouchEventsGestureRecognizer *sender = arg1;
	id point = [[sender touchLocations] objectAtIndex:0];
	CGPoint cgpoint = ((NSValue *)point).CGPointValue;
	if ([sender state] != UIGestureRecognizerStatePossible || CGPointEqualToPoint(cgpoint, last)) {
		%orig;
		return;
	}
	int x = cgpoint.x;
	int y = cgpoint.y;
	if (focus && ![inputDict objectForKey:focus]) {
		NSDictionary *data = @{@"field":focus,
								@"text":[[NSMutableString alloc] init]};
		inputDict[focus] = data;
	}
	if (focus) {
		inputString = inputDict[focus][@"text"];
	}
	if (x >= 110 && x <= 530 && y >= 140 && y <= 195) {
		focus = @"Reference Number";
	} else if (x >= 110 && x <= 530 && y >= 210 && y <= 260) {
		focus = @"Password";
	} else if (x >= 90 && x <= 205 && y >= 445 && y <= 555) {
		if (focus) {
			[inputString appendString:keyMap[0]];
		}
	} else if (x >= 230 && x <= 345 && y >= 445 && y <= 555) {
		if (focus) {
			[inputString appendString:keyMap[1]];
		}
	} else if (x >= 390 && x <= 505 && y >= 445 && y <= 555) {
		if (focus) {
			[inputString appendString:keyMap[2]];
		}
	} else if (x >= 525 && x <= 640 && y >= 445 && y <= 555) {
		if (focus) {
			[inputString appendString:keyMap[3]];
		}
	} else if (x >= 670 && x <= 790 && y >= 445 && y <= 555) {
		if (focus) {
			[inputString appendString:keyMap[4]];
		}
	} else if (x >= 825 && x <= 940 && y >= 445 && y <= 555) {
		if (focus && [inputString length] > 0) {
			[inputString replaceCharactersInRange:NSMakeRange([inputString length]-1,1) withString:@""];
		}
	} else if (x >= 90 && x <= 205 && y >= 590 && y <= 705) {
		if (focus) {
			[inputString appendString:keyMap[5]];
		}
	} else if (x >= 230 && x <= 345 && y >= 590 && y <= 705) {
		if (focus) {
			[inputString appendString:keyMap[6]];
		}
	} else if (x >= 390 && x <= 505 && y >= 590 && y <= 705) {
		if (focus) {
			[inputString appendString:keyMap[7]];
		}
	} else if (x >= 525 && x <= 640 && y >= 590 && y <= 705) {
		if (focus) {
			[inputString appendString:keyMap[8]];
		}
	} else if (x >= 670 && x <= 790 && y >= 590 && y <= 705) {
		if (focus) {
			[inputString appendString:keyMap[9]];
		}
	} else if (x >= 825 && x <= 940 && y >= 590 && y <= 705) {
		focus = nil;
	} else if (y >= 400) {
		;
	} else if (y >= 375 && y <= 400 && x <= 90) {
		NSLog(@"Prev");
	} else if (y >= 375 && y <= 400 && x <= 180 && x >= 90) {
		NSLog(@"Next");
	} else {
		focus = nil;
	}
	if (focus) {
		NSLog(@"%@", inputDict);
	}
	return %orig;
}

%end // com.db.pbc.mibanco

/*
 * QR-Code reader com.netcetera.s-id-check and de.dkb.cardsecure
 */

%hook TransaktRegisterQRViewController

- (void)captureOutput:(id)output didOutputMetadataObjects:(id)metadataObjects fromConnection:(id)connection {
	NSLog(@"Metadata: %@", metadataObjects);
	%orig;
}

%end

/*
 * QR-Code reader de.olb.phototan
 */

%hook QRCodeScannerWrapper

- (void) qrCodeScannerSDKController:(id)arg0 didScanResult:(id)arg1 withCodeType:(int)arg2 {
	NSLog(@"Scan result: %@", arg1);
	%orig;
}

%end

%ctor {
	appFolderPath = [[NSBundle mainBundle] resourcePath].stringByDeletingLastPathComponent;

	NSFileManager *fileManager = [NSFileManager defaultManager];
	//document directory of sandbox
	documentDirectory = 
		[[[fileManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask]lastObject]path]
		.stringByDeletingLastPathComponent;

	NSArray* blacklist = [NSArray arrayWithObjects:
			@"com.apple.AppStore",
			@"com.apple.itunesstored",
			@"com.apple.mobilemail",
			@"com.apple.AdSheetPhone",
			@"com.apple.ios.StoreKitUIService",
			@"com.apple.SpringBoard",
			@"/usr/bin/aaexecutord",
			@"com.apple.managedconfiguration.profiled",
			@"com.apple.Search.framework",
			@"com.apple.sociald.SocialDaemon",
			@"com.apple.social.remoteui.SocialUIService",
			@"com.apple.backupd",
			@"com.apple.syncdefaultsd",
			@"com.apple.assetsd",
			@"com.apple.calaccessd",
			@"com.apple.passd",
			@"com.apple.Preferences",
			@"com.apple.gamecenter.GameCenterUIService",
			@"com.apple.AssistantServices",
			@"com.apple.commcentermobilehelper",
			@"com.apple.mediastream.mstreamd",
			@"com.saurik.Cydia",
			@"/usr/libexec/ptpd",
			@"/usr/libexec/sandboxd",
			@"/usr/libexec/webinspectord",
			@"/usr/libexec/librariand",
			@"/usr/libexec/misd",
			@"/usr/libexec/timed",
			@"/System/Library/CoreServices/ReportCrash",
			@"/System/Library/Frameworks/AddressBook.framework/Support/ABDatabaseDoctor",
			@"/System/Library/Frameworks/UIKit.framework/Support/pasteboardd",
			@"/System/Library/PrivateFrameworks/VoiceServices.framework/Support/vsassetd",
			@"/System/Library/PrivateFrameworks/VoiceServices.framework/Support/voiced",
			nil];

	NSLog(@"BundleID: %@", [[NSBundle mainBundle] bundleIdentifier]);
	NSLog(@"Path: %@", [[NSBundle mainBundle] executablePath]);

	if ([blacklist containsObject:[[NSBundle mainBundle] bundleIdentifier]]
            || [blacklist containsObject:[[NSBundle mainBundle] executablePath]]) {

            disabled = YES;
            return;

    } else {

    	NSDictionary* taskInfo = [[AAClientLib sharedInstance] taskInfo];
		if (taskInfo == nil) {

			// Used during development, results are not delivered to the DiOS backend
			NSLog(@"Standalone Mode");

		} else if ([[taskInfo objectForKey:@"bundleId"] isEqualToString:[[NSBundle mainBundle] bundleIdentifier]]) {

			// In DiOS mode all results will be delivered to the DiOS backend when app exits
			[[Broker sharedInstance] registerExitHook];

		}
	}
}
