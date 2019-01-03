//
//  ALXRSAAsymmetricEncryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXRSAAsymmetricEncryptor.h"

@implementation ALXRSAAsymmetricEncryptor

- (ALXAsymmetricCryptoAlgorithm)algorithm{
    return ALXAsymmetricCryptoAlgorithmRSA;
}

- (NSString *)encrypt:(NSString *)plaintext{
    [super encrypt:plaintext];
    
    // TODO:Alexgao---公钥加密
    
    return @"";
}

@end
