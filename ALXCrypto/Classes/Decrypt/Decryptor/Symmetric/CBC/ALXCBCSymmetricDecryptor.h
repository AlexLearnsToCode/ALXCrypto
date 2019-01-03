//
//  ALXCBCSymmetricDecryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXSymmetricDecryptor.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXCBCSymmetricDecryptor : ALXSymmetricDecryptor

@property (nonatomic, copy) NSString *iv;

@end

NS_ASSUME_NONNULL_END
