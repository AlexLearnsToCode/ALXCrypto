//
//  ALXSymmetricCryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXSymmetricCryptor.h"

@implementation ALXSymmetricCryptor

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }

    return plaintext;
}

- (NSString *)decrypt:(NSString *)ciphertext{
    if (!ciphertext.length) {
        NSAssert(ciphertext.length > 0, @"invalid argument 'ciphertext'.");
        return @"";
    }
    
    return ciphertext;
}

@end
