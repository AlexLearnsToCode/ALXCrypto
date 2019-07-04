//
//  ALXAsymmetricCryptoUtil.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/7/4.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class ALXAsymmetricCryptor;
@interface ALXAsymmetricCryptoUtil : NSObject

@property (nonatomic) SecKeyRef publicSecKey;
@property (nonatomic) size_t blockSize;
@property (nonatomic) size_t maxPlainTextSize;

@property (nonatomic) SecKeyRef privateSecKey;

@property (nonatomic) SecPadding secPadding;

- (instancetype)initWithAsymmetricCryptor:(ALXAsymmetricCryptor *)asymmetricCryptor;

@end

NS_ASSUME_NONNULL_END
