//
//  ALXCBCSymmetricEncryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXSymmetricEncryptor.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXCBCSymmetricEncryptor : ALXSymmetricEncryptor

@property (nonatomic, copy) NSString *iv;

@end

NS_ASSUME_NONNULL_END
