//
//  ALXECBSymmetricDecryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXECBSymmetricDecryptor.h"

@implementation ALXECBSymmetricDecryptor

- (ALXSymmetricCryptoMode)mode{
    return ALXSymmetricCryptoModeECB;
}

- (NSString *)decrypt:(NSString *)ciphertext{
    [super decrypt:ciphertext];
    
    // TODO:Alexgao---解密
    
    return @"";
}

@end
