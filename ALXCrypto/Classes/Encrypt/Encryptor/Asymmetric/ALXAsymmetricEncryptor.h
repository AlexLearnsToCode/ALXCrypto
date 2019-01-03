//
//  ALXAsymmetricEncryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXEncryptor.h"
#import "ALXCryptoDefines.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXAsymmetricEncryptor : ALXEncryptor

@property (nonatomic, readonly) ALXAsymmetricCryptoAlgorithm algorithm;

#pragma mark - Public Key
@property (nonatomic, copy) NSString *publicKey;
@property (nonatomic, copy) NSString *publicKeyFilePath;

@end

NS_ASSUME_NONNULL_END
