//
//  ALXCBCSymmetricEncryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXCBCSymmetricEncryptor.h"

@implementation ALXCBCSymmetricEncryptor

- (ALXSymmetricCryptoMode)mode{
    return ALXSymmetricCryptoModeCBC;
}

- (NSString *)encrypt:(NSString *)plaintext{
    [super encrypt:plaintext];
    
    // TODO:Alexgao---处理iv,加密
    
    return @"";
}



@end
