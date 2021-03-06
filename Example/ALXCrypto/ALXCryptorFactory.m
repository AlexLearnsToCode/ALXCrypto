//
//  ALXCryptorFactory.m
//  ALXCrypto_Example
//
//  Created by 高昊 on 2019/1/6.
//  Copyright © 2019 alexlearnstocode. All rights reserved.
//

#import "ALXCryptorFactory.h"

@implementation ALXCryptorFactory

#pragma mark - Hash
+ (ALXHashCryptor *)hashCryptorWithAlgorithm:(ALXHashAlgorithm)hashAlgorithm{
    ALXHashCryptor *hashCrypto = [[ALXHashCryptor alloc] init];
    hashCrypto.algorithm = hashAlgorithm;
    return hashCrypto;
}

+ (ALXHMACCryptor *)hmacCryptorWithAlgorithm:(ALXHMACAlgorithm)hmacAlgorithm key:(NSString *)key{
    ALXHMACCryptor *hmacCryptor = [[ALXHMACCryptor alloc] init];
    hmacCryptor.algorithm = hmacAlgorithm;
    hmacCryptor.key = key;
    return hmacCryptor;
}

#pragma mark - Symmetric
+ (ALXECBSymmetricCryptor *)ecbSymmetricCryptorWithAlgorithm:(ALXSymmetricCryptoAlgorithm)algorithm key:(NSString *)key padding:(ALXPKCSPadding)padding{
    ALXECBSymmetricCryptor *ecbCryptor = [[ALXECBSymmetricCryptor alloc] init];
    ecbCryptor.algorithm = algorithm;
    ecbCryptor.key = key;
    ecbCryptor.padding = padding;
    return ecbCryptor;
}

+ (ALXCBCSymmetricCryptor *)cbcSymmetricCryptorWithAlgorithm:(ALXSymmetricCryptoAlgorithm)algorithm key:(NSString *)key padding:(ALXPKCSPadding)padding iv:(NSString *)iv{
    ALXCBCSymmetricCryptor *cbcCryptor = [[ALXCBCSymmetricCryptor alloc] init];
    cbcCryptor.algorithm = algorithm;
    cbcCryptor.key = key;
    cbcCryptor.padding = padding;
    cbcCryptor.iv = iv;
    return cbcCryptor;
}

#pragma mark - Asymmetric
#pragma mark - *** Encryption ***
+ (ALXRSAAsymmetricCryptor *)rsaAsymmetricCryptorWithPublicKeyFilePath:(NSString *)publicKeyFilePath padding:(ALXAsymmetricCryptoPadding)padding{
    ALXRSAAsymmetricCryptor *rsaCryptor = [[ALXRSAAsymmetricCryptor alloc] init];
    rsaCryptor.publicKeyFilePath = publicKeyFilePath;
    rsaCryptor.padding = padding;
    return rsaCryptor;
}

#pragma mark - *** Decryption ***
+ (ALXRSAAsymmetricCryptor *)rsaAsymmetricCryptorWithPrivateKeyFile:(NSString *)privateKeyFilePath padding:(ALXAsymmetricCryptoPadding)padding{
    ALXRSAAsymmetricCryptor *rsaCryptor = [[ALXRSAAsymmetricCryptor alloc] init];
    rsaCryptor.privateKeyFilePath = privateKeyFilePath;
    rsaCryptor.padding = padding;
    return rsaCryptor;
}

#pragma mark - *** Signature ***
+ (ALXRSAAsymmetricCryptor *)rsaAsymmetricCryptorWithPrivateKeyFile:(NSString *)privateKeyFilePath
                                                 signatureAlgorithm:(ALXAsymmetricCryptoSignatureAlgorithm)signatureAlgorithm {
    ALXRSAAsymmetricCryptor *rsaCryptor = [[ALXRSAAsymmetricCryptor alloc] init];
    rsaCryptor.privateKeyFilePath = privateKeyFilePath;
    rsaCryptor.signatureAlgorithm = signatureAlgorithm;
    return rsaCryptor;
}

#pragma mark - *** Verify ***
+ (ALXRSAAsymmetricCryptor *)rsaAsymmetricCryptorWithPublicKeyFilePath:(NSString *)publicKeyFilePath
                                                    signatureAlgorithm:(ALXAsymmetricCryptoSignatureAlgorithm)signatureAlgorithm {
    ALXRSAAsymmetricCryptor *rsaCryptor = [[ALXRSAAsymmetricCryptor alloc] init];
    rsaCryptor.publicKeyFilePath = publicKeyFilePath;
    rsaCryptor.signatureAlgorithm = signatureAlgorithm;
    return rsaCryptor;
}

@end
