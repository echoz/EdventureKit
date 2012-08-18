//
//  EDNTUAccount.m
//  EdventureKit
//
//  Created by Jeremy Foo on 18/8/12.
//  Copyright (c) 2012 Jeremy Foo. All rights reserved.
//

#import "EDNTUAccount.h"
#import "AFNetworking.h"
#import "LBCHTTPPostBody.h"

#define HTTP_USER_AGENT @"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_3; en-us) AppleWebKit/533.4+ (KHTML, like Gecko) Version/4.0.5 Safari/531.22.7"
#define AUTH_URL @"https://sso.wis.ntu.edu.sg/webexe88/owa/sso.asp"
#define AUTH_ERROR_STRING @"may be invalid or has expired"

#define TOKEN_URL @"https://sso.wis.ntu.edu.sg/webexe88/ntlm/sso_express.asp"
#define TOKEN_REGEX @"<input type=\"hidden\" name=\"p1\" value=\"(.*)\">\\s*<input type=\"hidden\" name=\"p2\" value=\"(.*)\">"
#define LEGAL_CHAR_TOESCAPE @" ()<>#%{}|\\^~[]`;/?:@=&$"

#define EDVENTURE_LOGIN_CHECK @"<input value=\"/ntu_post_login.html\" name=\"new_loc\" type=\"hidden\">"

NSString *const EDNTUErrorDomain = @"EDNTUErrorDomain";
NSString *const EDNTUAccountWISUnderlyingError = @"EDNTUAccountWISUnderlyingError";
NSString *const EDNTUAccountTokenUnderlyingError = @"EDNTUAccountTokenUnderlyingError";

@implementation EDNTUAccount {
    NSMutableArray *_cookies;
    NSMutableArray *_authCookies;
    NSString *_secretToken;
    NSRegularExpression *_tokenRegex;

    BOOL _wisAuth;
    BOOL _tokenAuth;
}
@synthesize username = _username, password = _password, domain = _domain;
@synthesize studentID = _studentID, authenticated = _authenticated;

#pragma mark - Object Life Cycle

-(id)initWithUsername:(NSString *)username password:(NSString *)password domain:(NSString *)domain {
    if ((self = [super init])) {
        self.username = username;
        self.password = password;
        self.domain = domain;

        _authenticated = NO;
        _studentID = nil;

        _cookies = [[NSMutableArray arrayWithCapacity:0] retain];
        _authCookies = [[NSMutableArray arrayWithCapacity:0] retain];
        _secretToken = nil;

        _tokenRegex = [[NSRegularExpression regularExpressionWithPattern:TOKEN_REGEX options:NSRegularExpressionAnchorsMatchLines error:nil] retain];
        NSLog(@"TOKENREGEX: %@", _tokenRegex);
    }
    return self;
}

-(void)dealloc {
    [_username release], _username = nil;
    [_password release], _password = nil;
    [_domain release], _domain = nil;

    [_studentID release], _studentID = nil;
    [_cookies release], _cookies = nil;
    [_authCookies release], _authCookies = nil;

    [_secretToken release], _secretToken = nil;
    [_tokenRegex release], _tokenRegex = nil;

    [super dealloc];
}

#pragma mark - Network Request

-(void)generatePostURLRequestForURL:(NSURL *)url postDictionary:(NSDictionary *)postValues completion:(void (^)(NSMutableURLRequest *urlRequest))completion {
    NSAssert1((completion != nil), @"Completion cannot be nil", nil);

    [LBCHTTPPostBody performAutomaticHTTPBodyGenerationOfParameters:postValues completion:^(BOOL isStreamFile, NSString *contentType, NSString *contentLength, id result, NSError *error) {
        if ((result) || (!isStreamFile)) {
            NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url
                                                                        cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData
                                                                    timeoutInterval:30.0];

            [request setValue:HTTP_USER_AGENT forHTTPHeaderField:@"User-Agent"];
            [request setValue:contentType forHTTPHeaderField:@"Content-Type"];
            [request setValue:contentLength forHTTPHeaderField:@"Content-Length"];
            request.HTTPBody = result;
            request.HTTPMethod = @"POST";

            completion([request autorelease]);

        } else {
            completion(nil);
        }
    }];
}

#pragma mark - Authentication

-(void)performSignOffWithCompletion:(EDNTUAccountAuthCompletionHandler)completion {
    
}

-(void)performAuthenticationWithCompletion:(EDNTUAccountAuthCompletionHandler)completion {
    if ((!self.isAuthenticated) || ([self.username length] == 0) || ([self.password length] == 0) || (self.domain == 0))
        return;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        dispatch_group_t authGroup = dispatch_group_create();

        _wisAuth = NO;
        _tokenAuth = NO;

        __block NSError *wisError = nil;
        __block NSError *tokenError = nil;
        
        dispatch_group_enter(authGroup);
        NSDictionary *dict = @{@"UserName" : self.username,  @"PIN" : self.password, @"Domain" : self.domain};
        [self generatePostURLRequestForURL:[NSURL URLWithString:AUTH_URL] postDictionary:dict completion:^(NSMutableURLRequest *urlRequest) {
            if (!urlRequest) {
                wisError = [NSError errorWithDomain:EDNTUAccountErrorDomain code:EDNTUAccountPOSTGenerationError userInfo:nil];
                dispatch_group_leave(authGroup);
                return;

            }

            // do wis
            AFHTTPRequestOperation *wisRequest = [[AFHTTPRequestOperation alloc] initWithRequest:urlRequest];

            [wisRequest setCompletionBlockWithSuccess:^(AFHTTPRequestOperation *operation, id responseObject) {
                // error!
                if ([operation.responseString rangeOfString:AUTH_ERROR_STRING].location != NSNotFound) {
                    wisError = [NSError errorWithDomain:EDNTUAccountErrorDomain code:EDNTUAccountWISSignOnError userInfo:nil];
                    dispatch_group_leave(authGroup);
                    return;
                }

                // we have a winner, save the authentication cookies!
                NSArray *cookies = [NSHTTPCookie cookiesWithResponseHeaderFields:[responseObject allHeaderFields] forURL:[NSURL URLWithString:AUTH_URL]];
                for (NSHTTPCookie *cookie in cookies) {
                    if ([cookie.domain isEqualToString:@".wis.ntu.edu.sg"] || [cookie.domain isEqualToString:@"edventure.ntu.edu.sg"])
                        [_authCookies addObject:cookie];
                }

                _wisAuth = YES;
                wisError = nil;
                dispatch_group_leave(authGroup);

            } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
                wisError = [NSError errorWithDomain:EDNTUAccountErrorDomain code:EDNTUAccountNetworkError userInfo:@{ NSUnderlyingErrorKey : error }];
                dispatch_group_leave(authGroup);
            }];
            
            [wisRequest start];
            [wisRequest release];
        }];

        dispatch_group_enter(authGroup);
        NSURLRequest *tokenURLRequest = [NSURLRequest requestWithURL:[NSURL URLWithString:TOKEN_URL]
                                                         cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData
                                                     timeoutInterval:30.0];

        AFHTTPRequestOperation *tokenRequest = [[AFHTTPRequestOperation alloc] initWithRequest:tokenURLRequest];
        [tokenRequest setAuthenticationChallengeBlock:^(NSURLConnection *connection, NSURLAuthenticationChallenge *challenge) {
            NSURLCredential *tokenCredential = [NSURLCredential credentialWithUser:self.username
                                                                          password:self.password
                                                                       persistence:NSURLCredentialPersistenceNone];
            [[challenge sender] useCredential:tokenCredential forAuthenticationChallenge:challenge];
        }];

        [tokenRequest setCompletionBlockWithSuccess:^(AFHTTPRequestOperation *operation, id responseObject) {
            NSArray *captureGroups = [_tokenRegex matchesInString:operation.responseString options:0 range:NSMakeRange(0, [operation.responseString length])];
            if ([captureGroups count] < 3) {
                tokenError = [NSError errorWithDomain:EDNTUAccountErrorDomain code:EDNTUAccountTokenSignOnError userInfo:nil];
                dispatch_group_leave(authGroup);
                return;
            }

            _studentID = [operation.responseString substringWithRange:[[captureGroups objectAtIndex:1] range]];
            _secretToken = [operation.responseString substringWithRange: [[captureGroups objectAtIndex:2] range]];
            
            tokenError = nil;
            _tokenAuth = YES;
            dispatch_group_leave(authGroup);

        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            tokenError = [NSError errorWithDomain:EDNTUAccountErrorDomain code:EDNTUAccountNetworkError userInfo:@{ NSUnderlyingErrorKey : error }];
            dispatch_group_leave(authGroup);
        }];
        
        [tokenRequest start];
        [tokenRequest release];

        dispatch_group_wait(authGroup, DISPATCH_TIME_FOREVER);
        dispatch_release(authGroup);

        if ((!_wisAuth) || (!_tokenAuth)) {
            _authenticated = NO;

            if (completion)
                dispatch_async(dispatch_get_main_queue(), ^{
                    if ((wisError) && (tokenError)) {
                        completion(NO, [NSError errorWithDomain:EDNTUErrorDomain code:EDNTUAccountBatchOperationError userInfo:@{ EDNTUAccountWISUnderlyingError : wisError, EDNTUAccountTokenUnderlyingError : tokenError }]);
                        return;
                    }

                    if (wisError) {
                        completion(NO, wisError);
                        return;
                    }

                    if (tokenError) {
                        completion(NO, tokenError);
                        return;
                    }
                });

            return;
        }

        _authenticated = YES;
        if (completion)
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(YES, nil);
            });
    });

}

@end
