//
//  ALXAsymmetricDecryptor.h
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXDecryptor.h"
#import "ALXCryptoDefines.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALXAsymmetricDecryptor : ALXDecryptor

@property (nonatomic, readonly) ALXAsymmetricCryptoAlgorithm algorithm;

// !!!:Alexgao---iOS 暂不支持私钥加密,公钥解密
#pragma mark - Private Key
@property (nonatomic, copy) NSString *privateKey;
@property (nonatomic, copy) NSString *privateKeyFilePath;
@property (nonatomic, copy) NSString *password;

@end

NS_ASSUME_NONNULL_END
