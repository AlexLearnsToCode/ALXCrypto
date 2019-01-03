//
//  ALXCBCSymmetricDecryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXCBCSymmetricDecryptor.h"

@implementation ALXCBCSymmetricDecryptor

- (ALXSymmetricCryptoMode)mode{
    return ALXSymmetricCryptoModeCBC;
}

- (NSString *)decrypt:(NSString *)ciphertext{
    [super decrypt:ciphertext];
    
    // TODO:Alexgao---处理iv,解密
    
    return @"";
}

@end
