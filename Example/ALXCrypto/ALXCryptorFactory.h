//
//  ALXCryptorFactory.h
//  ALXCrypto_Example
//
//  Created by 高昊 on 2019/1/6.
//  Copyright © 2019 alexlearnstocode. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <ALXCrypto/ALXCrypto.h>

NS_ASSUME_NONNULL_BEGIN

@interface ALXCryptorFactory : NSObject

#pragma mark - Hash
+ (ALXHashCryptor *)hashCryptorWithAlgorithm:(ALXHashAlgorithm)hashAlgorithm;
+ (ALXHMACCryptor *)hmacCryptorWithAlgorithm:(ALXHMACAlgorithm)hmacAlgorithm key:(NSString *)key;

#pragma mark - Symmetric
+ (ALXECBSymmetricCryptor *)ecbSymmetricCryptorWithAlgorithm:(ALXSymmetricCryptoAlgorithm)algorithm key:(NSString *)key padding:(ALXPKCSPadding)padding;
+ (ALXCBCSymmetricCryptor *)cbcSymmetricCryptorWithAlgorithm:(ALXSymmetricCryptoAlgorithm)algorithm key:(NSString *)key padding:(ALXPKCSPadding)padding iv:(NSString *)iv;

#pragma mark - Asymmetric
#pragma mark - *** Encryption ***
+ (ALXRSAAsymmetricCryptor *)rsaAsymmetricCryptorWithPublicKeyFilePath:(NSString *)publicKeyFilePath padding:(ALXAsymmetricCryptoPadding)padding;
#pragma mark - *** Decryption ***
+ (ALXRSAAsymmetricCryptor *)rsaAsymmetricCryptorWithPrivateKeyFile:(NSString *)privateKeyFilePath padding:(ALXAsymmetricCryptoPadding)padding;
#pragma mark - *** Signature ***
+ (ALXRSAAsymmetricCryptor *)rsaAsymmetricCryptorWithPrivateKeyFile:(NSString *)privateKeyFilePath
                                                 signatureAlgorithm:(ALXAsymmetricCryptoSignatureAlgorithm)signatureAlgorithm;

#pragma mark - *** Verify ***
+ (ALXRSAAsymmetricCryptor *)rsaAsymmetricCryptorWithPublicKeyFilePath:(NSString *)publicKeyFilePath
                                                    signatureAlgorithm:(ALXAsymmetricCryptoSignatureAlgorithm)signatureAlgorithm;


@end

NS_ASSUME_NONNULL_END
