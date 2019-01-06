//
//  ALXHMACCryptoUtil.h
//  ALXCrypto
//
//  Created by 高昊 on 2019/1/6.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

NS_ASSUME_NONNULL_BEGIN

@class ALXHMACCryptor;
@interface ALXHMACCryptoUtil : NSObject

@property (nonatomic) int resultLength;
@property (nonatomic) CCHmacAlgorithm hmacAlgorithm;

- (instancetype)initWithHMACCryptor:(ALXHMACCryptor *)hmacCryptor;

- (NSString *)hmacStringWithBytes:(uint8_t *)result;

@end

NS_ASSUME_NONNULL_END
