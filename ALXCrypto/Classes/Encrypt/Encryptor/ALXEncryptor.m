//
//  ALXEncryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXEncryptor.h"

@implementation ALXEncryptor

- (NSString *)encrypt:(NSString *)plaintext {
    if (!plaintext.length) {
        NSAssert(plaintext.length > 0, @"invalid argument 'plaintext'.");
        return @"";
    }
    return plaintext;
}

@end
