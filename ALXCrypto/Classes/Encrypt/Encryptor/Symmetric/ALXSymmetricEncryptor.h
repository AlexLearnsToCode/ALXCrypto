//
//  ALXSymmetricEncryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXEncryptor.h"
#import "ALXCryptoDefines.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXSymmetricEncryptor : ALXEncryptor

@property (nonatomic, readonly) ALXSymmetricCryptoMode mode;

@property (nonatomic) CCAlgorithm algorithm;
@property (nonatomic, copy) NSString *key;
@property (nonatomic) ALXPKCSPadding padding;

@end

NS_ASSUME_NONNULL_END
