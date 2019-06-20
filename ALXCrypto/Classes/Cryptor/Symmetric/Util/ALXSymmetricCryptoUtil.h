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
@property (nonatomic) CCAlgorithm algorithm;
@property (nonatomic) CCPadding padding;
@property (nonatomic) int blockSize;
@property (nonatomic) int keySize;

- (instancetype)initWithSymmetricCryptor:(ALXSymmetricCryptor *)symmetricCryptor;

- (NSString *)addPaddingToString:(NSString *)plaintext;
- (NSString *)removePaddingFromString:(NSString *)ciphertext;

- (NSString *)resultStringWithBytes:(void *)result length:(size_t)length;

@end

NS_ASSUME_NONNULL_END
