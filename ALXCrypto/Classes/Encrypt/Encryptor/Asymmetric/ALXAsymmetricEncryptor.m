//
//  ALXAsymmetricEncryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXAsymmetricEncryptor.h"

@implementation ALXAsymmetricEncryptor

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    
    return plaintext;
}

@end
