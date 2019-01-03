//
//  ALXCBCSymmetricEncryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXCBCSymmetricEncryptor.h"

static CCOptions ALXOptionsFromModeAndPadding(CCMode mode, ALXPKCSPadding padding) {
    if (mode == kCCModeECB) {
        switch (padding) {
            case ALXPKCSNoPadding:{
                return 0x0000 | kCCModeECB;
            }
            case ALXPKCS7Padding:{
                return kCCOptionPKCS7Padding | kCCModeECB;
            }
            default:
                return 0x0000 | kCCModeECB;
        }
    } else if (mode == kCCModeCBC) {
        switch (padding) {
            case ALXPKCSNoPadding:{
                return 0x0000;
            }
            case ALXPKCS7Padding:{
                return kCCOptionPKCS7Padding;
            }
            default:
                return 0x0000;
        }
    }
    return 0x0000;
}

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
