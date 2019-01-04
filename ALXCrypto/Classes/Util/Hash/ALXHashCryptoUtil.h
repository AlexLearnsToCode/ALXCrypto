//
//  ALXHashCryptoUtil.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

NS_ASSUME_NONNULL_BEGIN

@class ALXHashCryptor;
@class ALXHMACEncryptor;
@interface ALXHashCryptoUtil : NSObject

@property (nonatomic) int resultLength;
@property (nonatomic) BOOL uppercase;

@property (nonatomic) CCHmacAlgorithm hmacAlgorithm;

- (instancetype)initWithHashCryptor:(ALXHashCryptor *)hashCryptor;
//- (instancetype)initWithHmacCryptor:(ALXHMACEncryptor *)hmacCryptor;

- (NSString *)hashStringWithBytes:(uint8_t *)result;

@end

NS_ASSUME_NONNULL_END
