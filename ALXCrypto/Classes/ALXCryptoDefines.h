//
//  ALXCryptoDefines.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import <CommonCrypto/CommonCrypto.h>

#pragma mark - Hash

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

#pragma mark - Symmetric

typedef NS_ENUM(NSInteger, ALXPKCSPadding) {
    ALXPKCSNoPadding = 0,
    ALXPKCS5Padding,
    ALXPKCS7Padding = ALXPKCS5Padding
};


#pragma mark - Asymmetric

typedef NS_ENUM(NSInteger, ALXAsymmetricCryptoAlgorithm) {
    ALXAsymmetricCryptoAlgorithmRSA = 1,
};
