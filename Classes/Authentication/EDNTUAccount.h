//
//  EDNTUAccount.h
//  EdventureKit
//
//  Created by Jeremy Foo on 18/8/12.
//  Copyright (c) 2012 Jeremy Foo. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef void (^EDNTUAccountAuthCompletionHandler)(BOOL success, NSError *error);

extern NSString *const EDNTUAccountErrorDomain;

typedef enum {
    EDNTUAccountNetworkError,
    EDNTUAccountPOSTGenerationError,
    EDNTUAccountAlreadyAuthenticatedError,
    EDNTUAccountTokenSignOnError,
    EDNTUAccountWISSignOnError,
    EDNTUAccountEdventureError
} EDNTUAccountError;

@interface EDNTUAccount : NSObject
@property (nonatomic, copy) NSString *username;
@property (nonatomic, copy) NSString *password;
@property (nonatomic, copy) NSString *domain;

@property (readonly) NSString *studentID;
@property (readonly, getter = isAuthenticated) BOOL authenticated;

-(id)initWithUsername:(NSString *)username password:(NSString *)password domain:(NSString *)domain;
-(void)performAuthenticationWithCompletion:(EDNTUAccountAuthCompletionHandler)completion;
-(void)performSignOffWithCompletion:(EDNTUAccountAuthCompletionHandler)completion;
@end
