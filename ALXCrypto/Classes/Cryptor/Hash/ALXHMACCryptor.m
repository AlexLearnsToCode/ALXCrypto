//
//  ALXHMACCryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXHMACCryptor.h"
#import "ALXHMACCryptoUtil.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation ALXHMACCryptor

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    const char *input = plaintext.UTF8String;
    
    ALXHMACCryptoUtil *hmacUtil = [[ALXHMACCryptoUtil alloc] initWithHMACCryptor:self];
    if (!hmacUtil) {
        return @"";
    }
    
    const char *keyData = self.key.UTF8String;
    unsigned char result[hmacUtil.resultLength];
    
    CCHmac(hmacUtil.hmacAlgorithm, keyData, strlen(keyData), input, strlen(input), result);
    
    return [hmacUtil hmacStringWithBytes:result];
}

@end
