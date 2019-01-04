//
//  ALXAsymmetricCryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXCryptor.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, ALXAsymmetricCryptoAlgorithm) {
    ALXAsymmetricCryptoAlgorithmRSA = 1,
};

@interface ALXAsymmetricCryptor : ALXCryptor<ALXDecrypt>

@property (nonatomic, readonly) ALXAsymmetricCryptoAlgorithm algorithm;

#pragma mark - Encrypt - Public Key
@property (nonatomic, copy) NSString *publicKey;
@property (nonatomic, copy) NSString *publicKeyFilePath;

// !!!:Alexgao---iOS 暂不支持私钥加密,公钥解密
#pragma mark - Decrypt - Private Key
@property (nonatomic, copy) NSString *privateKey;
@property (nonatomic, copy) NSString *privateKeyFilePath;
@property (nonatomic, copy) NSString *password;

@end

NS_ASSUME_NONNULL_END
