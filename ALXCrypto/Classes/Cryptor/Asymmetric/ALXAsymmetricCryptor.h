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

typedef NS_ENUM(NSInteger, ALXAsymmetricCryptoType) {
    ALXAsymmetricCryptorTypeEncryption,    // 公钥加密, 私钥解密
    // !!!:Alexgao---为了避免搞混,将签名和验签 提出来做独立的方法
//    ALXAsymmetricCryptorTypeSignature    // 私钥加密, 公钥解密, 比对hash
};

typedef NS_ENUM(NSInteger, ALXAsymmetricCryptoPadding) {
    ALXAsymmetricCryptoPaddingNone,    // 明文最大长度为 blockSize
    ALXAsymmetricCryptoPaddingPKCS1,    // 明文最大长度为 blockSize - 11
    ALXAsymmetricCryptoPaddingOAEP    // 明文最大长度为 blockSize - 42
};

typedef NS_ENUM(NSInteger, ALXAsymmetricCryptoSignatureAlgorithm) {
    ALXAsymmetricCryptoSignatureAlgorithmSHA1,
    ALXAsymmetricCryptoSignatureAlgorithmSHA224,
    ALXAsymmetricCryptoSignatureAlgorithmSHA256,
    ALXAsymmetricCryptoSignatureAlgorithmSHA384,
    ALXAsymmetricCryptoSignatureAlgorithmSHA512
};

@interface ALXAsymmetricCryptor : ALXCryptor<ALXDecrypt>

@property (nonatomic, readonly) ALXAsymmetricCryptoAlgorithm algorithm;

@property (nonatomic, readonly) ALXAsymmetricCryptoType cryptoType;

@property (nonatomic) ALXAsymmetricCryptoPadding padding;

@property (nonatomic) ALXAsymmetricCryptoSignatureAlgorithm signatureAlgorithm;

#pragma mark - Encrypt - Public Key
/** der文件路径 */
@property (nonatomic, copy) NSString *publicKeyFilePath;

#pragma mark - Decrypt - Private Key
/** p12文件路径 */
@property (nonatomic, copy) NSString *privateKeyFilePath;
/** p12密码 */
@property (nonatomic, copy) NSString *password;

#pragma mark - Signature
/** 用私钥对原始字符串签名 */
- (NSString *)signWithRawString:(NSString *)rawString;
/** 用公钥对签名过的字符串验签 */
- (BOOL)verifyWithSignedString:(NSString *)signedString;

@end

NS_ASSUME_NONNULL_END
