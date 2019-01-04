//
//  ALXSymmetricCryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXCryptor.h"
#import <CommonCrypto/CommonCrypto.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, ALXPKCSPadding) {
    ALXPKCSNoPadding = 0,
    ALXPKCS5Padding,
    ALXPKCS7Padding = ALXPKCS5Padding
};


@interface ALXSymmetricCryptor : ALXCryptor<ALXDecrypt>

@property (nonatomic, readonly) CCMode mode;

@property (nonatomic) CCAlgorithm algorithm;
@property (nonatomic, copy) NSString *key;
@property (nonatomic) ALXPKCSPadding padding;

@end

NS_ASSUME_NONNULL_END
