//
//  ALXRSAAsymmetricDecryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXRSAAsymmetricDecryptor.h"

@implementation ALXRSAAsymmetricDecryptor

- (ALXAsymmetricCryptoAlgorithm)algorithm{
    return ALXAsymmetricCryptoAlgorithmRSA;
}

- (NSString *)decrypt:(NSString *)ciphertext{
    [super decrypt:ciphertext];
    
    // TODO:Alexgao---私钥解密
    
    return @"";
}

@end
