//
//  ALXAsymmetricSignatureUtil.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/7/4.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class ALXAsymmetricCryptor;
@interface ALXAsymmetricSignatureUtil : NSObject

@property (nonatomic) SecPadding secPadding;

- (instancetype)initWithAsymmetricCryptor:(ALXAsymmetricCryptor *)asymmetricCryptor;

@end

NS_ASSUME_NONNULL_END
