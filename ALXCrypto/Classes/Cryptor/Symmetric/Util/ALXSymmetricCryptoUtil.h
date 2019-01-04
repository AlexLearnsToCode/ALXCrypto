//
//  ALXSymmetricCryptoUtil.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

NS_ASSUME_NONNULL_BEGIN

@class ALXSymmetricCryptor;
@interface ALXSymmetricCryptoUtil : NSObject

@property (nonatomic) CCOperation operation;
@property (nonatomic) CCOptions options;

- (instancetype)initWithSymmetricCryptor:(ALXSymmetricCryptor *)symmetricCryptor;

- (NSString *)resultStringWithBytes:(void *)result length:(size_t)length;

@end

NS_ASSUME_NONNULL_END
