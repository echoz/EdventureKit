//
//  EVKAccount.h
//  EdventureKit
//
//  Created by Jeremy Foo on 18/8/12.
//  Copyright (c) 2012 Jeremy Foo. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef void (^EVKAccountAuthCompletionHandler)(BOOL success, NSError *error);

extern NSString *const EVKAccountErrorDomain;
extern NSString *const EVKAccountWISUnderlyingError;
extern NSString *const EVKAccountTokenUnderlyingError;

typedef enum {
    EVKAccountBatchOperationError,
    EVKAccountNetworkError,
    EVKAccountPOSTGenerationError,
    EVKAccountInvalidCredentialsError,
    EVKAccountAlreadyAuthenticatedError,
    EVKAccountNotAutnenticatedError,
    EVKAccountTokenSignOnError,
    EVKAccountWISSignOnError,
    EVKAccountEdventureError
} EVKAccountError;

@interface EVKAccount : NSObject
@property (nonatomic, copy) NSString *username;
@property (nonatomic, copy) NSString *password;
@property (nonatomic, copy) NSString *domain;

@property (readonly) NSString *studentID;
@property (readonly) NSString *secretToken;
@property (readonly) NSArray *authCookies;

@property (readonly, getter = isAuthenticated) BOOL authenticated;

-(id)initWithUsername:(NSString *)username password:(NSString *)password domain:(NSString *)domain;
-(void)performAuthenticationWithCompletion:(EVKAccountAuthCompletionHandler)completion;
-(void)performSignOffWithCompletion:(EVKAccountAuthCompletionHandler)completion;

-(void)generateAuthenticatedRequestForURL:(NSURL *)url postValues:(NSDictionary *)postValues completion:(void (^)(NSURLRequest *request, NSError *error))completion;
@end
