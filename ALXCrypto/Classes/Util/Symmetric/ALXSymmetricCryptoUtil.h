//
//  ALXSymmetricCryptoUtil.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import <Foundation/Foundation.h>
#import "ALXCryptoDefines.h"

NS_ASSUME_NONNULL_BEGIN

@class ALXSymmetricEncryptor;
@class ALXSymmetricDecryptor;
@interface ALXSymmetricCryptoUtil : NSObject

- (instancetype)initWithSymmetricEncryptor:(ALXSymmetricEncryptor *)encryptor;
- (instancetype)initWithSymmetricDecryptor:(ALXSymmetricDecryptor *)decryptor;

@end

NS_ASSUME_NONNULL_END
