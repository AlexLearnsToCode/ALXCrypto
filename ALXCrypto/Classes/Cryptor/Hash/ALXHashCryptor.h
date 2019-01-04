//
//  ALXHashCryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXCryptor.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, ALXHashAlgorithm) {
    /** md5_16_lowercase */
    ALXHashAlgorithmmd516 = 1,
    /** md5_32_lowercase */
    ALXHashAlgorithmmd532,
    /** MD5_16_uppercase */
    ALXHashAlgorithmMD516,
    /** MD5_32_uppercase */
    ALXHashAlgorithmMD532,
    ALXHashAlgorithmSHA1,
    ALXHashAlgorithmSHA256,
    ALXHashAlgorithmSHA384,
    ALXHashAlgorithmSHA512,
    ALXHashAlgorithmSHA224
};

@interface ALXHashCryptor : ALXCryptor

@property (nonatomic) ALXHashAlgorithm algorithm;

@end

NS_ASSUME_NONNULL_END
