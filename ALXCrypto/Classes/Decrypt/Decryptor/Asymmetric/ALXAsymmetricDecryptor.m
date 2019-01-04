//
//  ALXAsymmetricDecryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXAsymmetricDecryptor.h"

@implementation ALXAsymmetricDecryptor

- (NSString *)decrypt:(NSString *)ciphertext{
    if (![super decrypt:ciphertext].length) {
        return @"";
    }
    
    return ciphertext;
}

@end
