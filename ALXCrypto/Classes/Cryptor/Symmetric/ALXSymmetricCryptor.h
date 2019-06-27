//
//  ALXSymmetricCryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//  对称加密,暂时只支持block mode

#import "ALXCryptor.h"
#import <CommonCrypto/CommonCrypto.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, ALXSymmetricCryptoAlgorithm) {
    ALXSymmetricCryptoAlgorithmAES128,
    ALXSymmetricCryptoAlgorithmAES192,    // Apple暂不支持
    ALXSymmetricCryptoAlgorithmAES256,    // Apple暂不支持
    ALXSymmetricCryptoAlgorithmDES,
    ALXSymmetricCryptoAlgorithm3DES
};

typedef NS_ENUM(NSInteger, ALXPKCSPadding) {
    ALXPKCSNoPadding = 0,    // 使用noPadding的话, 明文长度(字节)必须是加密算法对应blockSize的整数倍
    ALXPKCSZeroPadding,    // 0x00
    ALXPKCS7Padding, //PKCS7Padding 向下兼容 PKCS5Padding
    ALXPKCS5Padding = ALXPKCS7Padding
};

// !!!:Alexgao---PKCS5Padding要求块的大小必须为8, PKCS7Padding对块的大小无要求(0-255)
// !!!:Alexgao---用PKCS5Padding填充加密的,PKCS7Padding可以解密
// !!!:Alexgao---用PKCS7Padding填充加密的,PKCS5Padding无法解密(取决于块大小)

@interface ALXSymmetricCryptor : ALXCryptor<ALXDecrypt>

@property (nonatomic, readonly) CCMode mode;

@property (nonatomic) ALXSymmetricCryptoAlgorithm algorithm;
@property (nonatomic, copy) NSString *key;
/** 填充模式,主要用于分组密码 */
@property (nonatomic) ALXPKCSPadding padding;

@end

NS_ASSUME_NONNULL_END
