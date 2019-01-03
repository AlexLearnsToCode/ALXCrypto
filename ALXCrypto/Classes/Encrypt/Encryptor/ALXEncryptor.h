//
//  ALXEncryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN

@protocol ALXEncrypt <NSObject>

- (NSString *)encrypt:(NSString *)plaintext;

@end

@interface ALXEncryptor : NSObject <ALXEncrypt>

@end

NS_ASSUME_NONNULL_END
