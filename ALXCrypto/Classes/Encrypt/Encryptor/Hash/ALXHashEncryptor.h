//
//  ALXHashEncryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXEncryptor.h"
#import "ALXCryptoDefines.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXHashEncryptor : ALXEncryptor

@property (nonatomic) ALXHashAlgorithm algorithm;

@end

NS_ASSUME_NONNULL_END
