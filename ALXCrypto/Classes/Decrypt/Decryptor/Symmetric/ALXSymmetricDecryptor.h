//
//  ALXSymmetricDecryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXDecryptor.h"
#import "ALXCryptoDefines.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXSymmetricDecryptor : ALXDecryptor

@property (nonatomic, readonly) ALXSymmetricCryptoMode mode;

@property (nonatomic) CCAlgorithm algorithm;
@property (nonatomic, copy) NSString *key;
@property (nonatomic) ALXPKCSPadding padding;

@end

NS_ASSUME_NONNULL_END
