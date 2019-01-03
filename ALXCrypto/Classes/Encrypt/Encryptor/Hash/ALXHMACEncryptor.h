//
//  ALXHMACEncryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXEncryptor.h"
#import "ALXCryptoDefines.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXHMACEncryptor : ALXEncryptor

@property (nonatomic) ALXHashAlgorithm algorithm;
@property (nonatomic, copy) NSString *key;

@end

NS_ASSUME_NONNULL_END
