//
//  AAClientLib.h
//  AAClientLib
//
//  Created by Andreas Weinlein on 12.12.12.
//  Copyright (c) 2012 Andreas Weinlein. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString *const AACResultTypeAppArchive;
extern NSString *const AACResultTypeCriteria;
extern NSString *const AACResultTypeScreenshot;
extern NSString *const AACResultTypeTcpdump;
extern NSString *const AACResultTypeStackTrace;
extern NSString *const AACResultTypeMethodCoverage;
extern NSString *const AACResultTypeString;

extern NSString *const AACNotificationAppExecutionStarted;
extern NSString *const AACNotificationAppExecutionFinished;

@interface NSDictionary(AAClientLib)

- (NSString *) runId;
- (NSString *) backendURL;

@end


@interface AAClientLib : NSObject

+ (AAClientLib*)sharedInstance;

//result has to be JSONSerializable
- (BOOL)saveResult:(id)result;
- (BOOL)saveResult:(id)result withType:(NSString*)type;
- (BOOL)saveResult:(id)result withType:(NSString*)type andTaskInfo:(NSDictionary*)taskInfo;

- (NSMutableURLRequest *)requestForResult:(id)result withType:(NSString *)type andTaskInfo:(NSDictionary*)taskInfo;

/*
 * All added blocks will be called after the corresponding event occured.
 * BEWARE: They will not be removed after a succesfull execution!!!
 * See AAPilotNotification.h for valid notifications and details
 */
- (void)registerForNotification:(NSString*)notification withBlock:(void(^)(void))block;
- (void)registerForAppExecutionRequestStartNotificationWithBlock:(void(^)(NSString *bundleId))block;


//set execution state
//set state to execution started. If scheduleRunning == TRUE, keep-alive messages will be sent to avoid timeouts
- (void)setAppExecutionHasStartedAndAutoScheduleSetRunning:(BOOL)scheduleRunning;
// set state to running. Will reset the timeout once
- (void)setAppExecutionRunning;
// set the state to finished
- (void)setAppExecutionHasFinished;


// request the execution of the app specified by the given bundleId
- (void)requestAppExecution:(NSString*)bundleId;

//get the current taskInfo dict
- (NSDictionary*)taskInfo;


@property(readonly) BOOL executionStartRequested;
@property(readonly) BOOL executionStarted;
@property(readonly) BOOL executionFinishRequested;

@end
