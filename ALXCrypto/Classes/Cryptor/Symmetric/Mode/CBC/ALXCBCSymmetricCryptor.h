//
//  ALXCBCSymmetricCryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXSymmetricCryptor.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXCBCSymmetricCryptor : ALXSymmetricCryptor

// !!!:Alexgao---偏移量必须是16字节
@property (nonatomic, copy) NSString *iv;

@end

NS_ASSUME_NONNULL_END
