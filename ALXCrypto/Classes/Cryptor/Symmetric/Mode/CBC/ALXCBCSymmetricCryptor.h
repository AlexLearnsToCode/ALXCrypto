//
//  ALXCBCSymmetricCryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXSymmetricCryptor.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXCBCSymmetricCryptor : ALXSymmetricCryptor

// !!!:Alexgao---偏移量可以是key的长度  参见 维基百科上初始化向量的解释
// AES 最少16
// DES 最少8
// 3DES 最少8
// 根据算法的blockSize来确定iv的最短长度
@property (nonatomic, copy) NSString *iv;

@end

NS_ASSUME_NONNULL_END
