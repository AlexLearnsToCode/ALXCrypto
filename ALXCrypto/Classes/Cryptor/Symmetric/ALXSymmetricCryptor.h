//
//  ALXSymmetricCryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXCryptor.h"
#import <CommonCrypto/CommonCrypto.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, ALXSymmetricCryptoAlgorithm) {
    ALXSymmetricCryptoAlgorithmAES128,
    ALXSymmetricCryptoAlgorithmAES192,
    ALXSymmetricCryptoAlgorithmAES256,
    ALXSymmetricCryptoAlgorithmDES,
    ALXSymmetricCryptoAlgorithm3DES
};

typedef NS_ENUM(NSInteger, ALXPKCSPadding) {
    ALXPKCSNoPadding = 0,
//    ALXPKCS5Padding,    // 暂不实现
    ALXPKCS7Padding
};

@interface ALXSymmetricCryptor : ALXCryptor<ALXDecrypt>

@property (nonatomic, readonly) CCMode mode;

@property (nonatomic) ALXSymmetricCryptoAlgorithm algorithm;
@property (nonatomic, copy) NSString *key;
@property (nonatomic) ALXPKCSPadding padding;

@end

NS_ASSUME_NONNULL_END
