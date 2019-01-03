//
//  ALXAsymmetricCryptoUtil.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import <Foundation/Foundation.h>
#import "ALXCryptoDefines.h"

NS_ASSUME_NONNULL_BEGIN

@class ALXAsymmetricEncryptor;
@class ALXAsymmetricDecryptor;
@interface ALXAsymmetricCryptoUtil : NSObject

- (instancetype)initWithAsymmetricEncryptor:(ALXAsymmetricEncryptor *)encryptor;
- (instancetype)initWithAsymmetricDecryptor:(ALXAsymmetricDecryptor *)decryptor;

@end

NS_ASSUME_NONNULL_END
