//
//  ALXCryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXCryptor.h"

@implementation ALXCryptor

- (NSString *)encrypt:(NSString *)plaintext {
    if (!plaintext.length) {
        NSAssert(plaintext.length > 0, @"invalid argument 'plaintext'.");
        return @"";
    }
    return plaintext;
}

@end
