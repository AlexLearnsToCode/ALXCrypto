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
    // !!!:Alexgao---结果不正确,原因未知,暂时注释
//    ALXHMACAlgorithmSHA384,
    ALXHMACAlgorithmSHA512
};

@interface ALXHMACCryptor : ALXCryptor

@property (nonatomic) ALXHMACAlgorithm algorithm;
@property (nonatomic, copy) NSString *key;

@end

NS_ASSUME_NONNULL_END
