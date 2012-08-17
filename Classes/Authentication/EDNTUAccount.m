//
//  EDNTUAccount.m
//  EdventureKit
//
//  Created by Jeremy Foo on 18/8/12.
//  Copyright (c) 2012 Jeremy Foo. All rights reserved.
//

#import "EDNTUAccount.h"
#import "AFNetworking.h"

#define HTTP_USER_AGENT @"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_3; en-us) AppleWebKit/533.4+ (KHTML, like Gecko) Version/4.0.5 Safari/531.22.7"
#define AUTH_URL @"https://sso.wis.ntu.edu.sg/webexe88/owa/sso.asp"
#define TOKEN_URL @"https://sso.wis.ntu.edu.sg/webexe88/ntlm/sso_express.asp"
#define TOKEN_REGEX @"<input type=\"hidden\" name=\"p1\" value=\"(.*)\">\\s*<input type=\"hidden\" name=\"p2\" value=\"(.*)\">"
#define LEGAL_CHAR_TOESCAPE @" ()<>#%{}|\\^~[]`;/?:@=&$"

#define EDVENTURE_LOGIN_CHECK @"<input value=\"/ntu_post_login.html\" name=\"new_loc\" type=\"hidden\">"

@implementation EDNTUAccount {
    NSMutableArray *_cookies;
    NSMutableArray *_authCookies;
    NSString *_secretToken;
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

    [super dealloc];
}

#pragma mark - Authentication

-(void)performSignOffWithCompletion:(EDNTUAccountAuthCompletionHandler)completion {
    
}

-(void)performAuthenticationWithCompletion:(EDNTUAccountAuthCompletionHandler)completion {
    if (self.isAuthenticated)
        return;


    // WIS first
    // then token
    // alongside edventure
    
}

@end
