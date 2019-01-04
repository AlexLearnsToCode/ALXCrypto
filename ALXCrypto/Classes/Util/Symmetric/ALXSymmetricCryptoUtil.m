//
//  ALXSymmetricCryptoUtil.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXSymmetricCryptoUtil.h"
#import "ALXSymmetricEncryptor.h"
#import "ALXSymmetricDecryptor.h"

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

@implementation ALXSymmetricCryptoUtil

- (NSString *)resultStringWithBytes:(void *)result length:(size_t)length{
    // Alexgao---resultData会自动释放buffer
    NSData *resultData = [NSData dataWithBytesNoCopy:result length:length];
    if (self.operation == kCCEncrypt) {
        return [[NSString alloc] initWithData:[resultData base64EncodedDataWithOptions:NSDataBase64Encoding64CharacterLineLength] encoding:NSUTF8StringEncoding];
    }else if (self.operation == kCCDecrypt) {
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    return @"";
}

- (instancetype)initWithSymmetricEncryptor:(ALXSymmetricEncryptor *)encryptor{
    self = [super init];
    if (self) {
        self.operation = kCCEncrypt;
        self.options = ALXOptionsFromModeAndPadding(encryptor.mode, encryptor.padding);
        
        if (!encryptor.key.length) {
            NSAssert(encryptor.key.length > 0, @"invalid argument 'key'");
            return nil;
        }
        
        // TODO:Alexgao---处理key的size
    }
    return self;
}

- (instancetype)initWithSymmetricDecryptor:(ALXSymmetricDecryptor *)decryptor{
    self = [super init];
    if (self) {
        self.operation = kCCDecrypt;
        self.options = ALXOptionsFromModeAndPadding(decryptor.mode, decryptor.padding);
        
        if (!decryptor.key.length) {
            NSAssert(decryptor.key.length > 0, @"invalid argument 'key'");
            return nil;
        }
        
        // TODO:Alexgao---处理key的size
        
    }
    return self;
}

@end
