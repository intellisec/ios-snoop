//
//  AAPilotNotifications.h
//  
//
//  Created by Andreas Weinlein on 05.12.12.
//
//

#ifndef _AAPilotNotifications_h
#define _AAPilotNotifications_h

#import <Foundation/NSArray.h>

// App-state related notifications

static NSString *const AAPilotAppWillStart = @"AAPilotAppWillStart";
static NSString *const AAPilotAppStarted = @"AAPilotAppStarted";
static NSString *const AAPilotAppWillExit = @"AAPilotAppWillExit";
static NSString *const AAPilotAppExited = @"AAPilotAppExited";


// Execution-state related notification

// These notifications will be received by SBSTAppExecutionManager
static NSString *const AAPilotAppExecutionStarted = @"AAPilotAppExecutionStarted";
static NSString *const AAPilotAppExecutionFinished = @"AAPilotAppExecutionFinished";

/// this notification can be used to reset the execution timeout
static NSString *const AAPilotAppExecutionRunning = @"AAPilotAppExecutionRunning";

/// the app execution timeout in minutes
///  the app will be killed after this period without a running notification
static NSInteger const AAPilotAppExectionTimeout = 1;


// These notifications will be sent by SBSTAppExecutionManager
static NSString *const AAPilotAppExecutionRequestStart = @"AAPilotAppExecutionRequestStart";
static NSString *const AAPilotAppExecutionRequestFinish = @"AAPilotAppExecutionRequestFinish";

static NSArray *AAPilotNotifications = nil;

/*
CHConstructor {
  AAPilotNotifications = @[
                           AAPilotAppWillStart,
                           AAPilotAppStarted,
                           AAPilotAppWillExit,
                           AAPilotAppExited,
                           AAPilotAppExecutionStarted,
                           AAPilotAppExecutionFinished,
                           AAPilotAppExecutionRunning,
                           AAPilotAppExecutionRequestStart,
                           AAPilotAppExecutionRequestFinish
                           ];
}
*/

#endif
