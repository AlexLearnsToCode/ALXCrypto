//
//  ALXAsymmetricEncryptorUtil.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class ALXAsymmetricCryptor;
@interface ALXAsymmetricEncryptorUtil : NSObject

@property (nonatomic) SecKeyRef seckey;

- (instancetype)initWithAsymmetricCryptor:(ALXAsymmetricCryptor *)asymmetricCryptor;

@end

NS_ASSUME_NONNULL_END
