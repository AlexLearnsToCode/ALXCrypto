//
//  ALXAsymmetricCryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXAsymmetricCryptor.h"

@implementation ALXAsymmetricCryptor

- (ALXAsymmetricCryptoType)cryptoType {
    return ALXAsymmetricCryptorTypeEncryption;
}


#pragma mark - Encryption

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

#pragma mark - Signature

- (NSString *)signWithRawString:(NSString *)rawString {
    if (!rawString.length) {
        return @"";
    }
    return rawString;
}

- (BOOL)verifyWithSignedString:(NSString *)signedString {
    if (!signedString.length) {
        return NO;
    }
    return YES;
}

@end
