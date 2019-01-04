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

@property (nonatomic) CCOperation operation;
@property (nonatomic) CCOptions options;

- (instancetype)initWithSymmetricEncryptor:(ALXSymmetricEncryptor *)encryptor;
- (instancetype)initWithSymmetricDecryptor:(ALXSymmetricDecryptor *)decryptor;

- (NSString *)resultStringWithBytes:(void *)result length:(size_t)length;

@end

NS_ASSUME_NONNULL_END
