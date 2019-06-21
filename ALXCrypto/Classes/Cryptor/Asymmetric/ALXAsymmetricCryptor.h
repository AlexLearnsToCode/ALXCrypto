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

typedef NS_ENUM(NSInteger, ALXAsymmetricCryptorType) {
    ALXAsymmetricCryptorTypeEncryption,    // 公钥加密
    ALXAsymmetricCryptorTypeSignature    // 私钥加密
};

@interface ALXAsymmetricCryptor : ALXCryptor<ALXDecrypt>

@property (nonatomic, readonly) ALXAsymmetricCryptoAlgorithm algorithm;

// TODO:Alexgao---缺少字段确定现在是 使用公钥加密还是使用私钥加密

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
