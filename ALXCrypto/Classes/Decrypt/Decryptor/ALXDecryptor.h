//
//  ALXDecryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol ALXDecrypt <NSObject>

- (NSString *)decrypt:(NSString *)ciphertext;

@end

@interface ALXDecryptor : NSObject <ALXDecrypt>

@end

NS_ASSUME_NONNULL_END
