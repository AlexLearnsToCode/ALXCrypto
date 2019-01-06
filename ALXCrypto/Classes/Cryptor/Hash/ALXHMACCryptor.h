//
//  ALXHMACCryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXCryptor.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, ALXHMACAlgorithm) {
    ALXHMACAlgorithmmd5,
    ALXHMACAlgorithmSHA1,
    ALXHMACAlgorithmSHA256,
    ALXHMACAlgorithmSHA512,
};

@interface ALXHMACCryptor : ALXCryptor

@property (nonatomic) ALXHMACAlgorithm algorithm;
@property (nonatomic, copy) NSString *key;

@end

NS_ASSUME_NONNULL_END
