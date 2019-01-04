//
//  ALXCryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol ALXEncrypt <NSObject>

- (NSString *)encrypt:(NSString *)plaintext;

@end

@protocol ALXDecrypt <NSObject>

- (NSString *)decrypt:(NSString *)ciphertext;

@end


@interface ALXCryptor : NSObject<ALXEncrypt>

@end

NS_ASSUME_NONNULL_END
