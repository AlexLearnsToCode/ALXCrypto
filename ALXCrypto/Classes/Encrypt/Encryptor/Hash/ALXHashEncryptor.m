//
//  ALXHashEncryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXHashEncryptor.h"
#import "ALXHashCryptoUtil.h"

@implementation ALXHashEncryptor

- (NSString *)encrypt:(NSString *)plaintext{
    
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    const char* input = [plaintext UTF8String];
    
    ALXHashCryptoUtil *hashUtil = [[ALXHashCryptoUtil alloc] initWithHashEncryptor:self];
    if (!hashUtil) {
        return @"";
    }
    
    unsigned char result[hashUtil.resultLength];
    
    switch (self.algorithm) {
        case ALXHashAlgorithmmd516:
        case ALXHashAlgorithmMD516:
        case ALXHashAlgorithmmd532:
        case ALXHashAlgorithmMD532:{
            CC_MD5(input, (CC_LONG)strlen(input), result);
            break;
        }
        case ALXHashAlgorithmSHA1:{
            CC_SHA1(input, (CC_LONG)strlen(input), result);
            break;
        }
        case ALXHashAlgorithmSHA256:{
            CC_SHA256(input, (CC_LONG)strlen(input), result);
            break;
        }
        case ALXHashAlgorithmSHA384:{
            CC_SHA384(input, (CC_LONG)strlen(input), result);
            break;
        }
        case ALXHashAlgorithmSHA512:{
            CC_SHA512(input, (CC_LONG)strlen(input), result);
            break;
        }
        case ALXHashAlgorithmSHA224:{
            CC_SHA224(input, (CC_LONG)strlen(input), result);
            break;
        }
        default:
            break;
    }
    
    return [hashUtil hashStringWithBytes:result];
}

@end
