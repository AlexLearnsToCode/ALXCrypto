//
//  ALXHMACCryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXHashCryptor.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXHMACCryptor : ALXHashCryptor

@property (nonatomic, copy) NSString *key;

@end

NS_ASSUME_NONNULL_END
