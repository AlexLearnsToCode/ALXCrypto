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
+ (ALXRSAAsymmetricCryptor *)rsaAsymmetricCryptorWithPublicKey:(NSString *)publicKey privateKey:(NSString *)privateKey;

@end

NS_ASSUME_NONNULL_END
