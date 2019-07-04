//
//  ALXAsymmetricSignatureUtil.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/7/4.
//

#import "ALXAsymmetricSignatureUtil.h"
#import "ALXAsymmetricCryptor.h"

static SecPadding ALXAsymmetricSecPaddingFromPadding(ALXAsymmetricCryptoSignatureAlgorithm signatureAlgorithm) {
    switch (signatureAlgorithm) {
        case ALXAsymmetricCryptoSignatureAlgorithmSHA1:
            return kSecPaddingPKCS1SHA1;
        case ALXAsymmetricCryptoSignatureAlgorithmSHA224:
            return kSecPaddingPKCS1SHA224;
        case ALXAsymmetricCryptoSignatureAlgorithmSHA256:
            return kSecPaddingPKCS1SHA256;
        case ALXAsymmetricCryptoSignatureAlgorithmSHA384:
            return kSecPaddingPKCS1SHA384;
        case ALXAsymmetricCryptoSignatureAlgorithmSHA512:
            return kSecPaddingPKCS1SHA512;
    }
}

@implementation ALXAsymmetricSignatureUtil

- (instancetype)initWithAsymmetricCryptor:(ALXAsymmetricCryptor *)asymmetricCryptor{
    self = [super init];
    if (self) {
        self.secPadding = ALXAsymmetricSecPaddingFromPadding(asymmetricCryptor.signatureAlgorithm);
    }
    return self;
}

@end
