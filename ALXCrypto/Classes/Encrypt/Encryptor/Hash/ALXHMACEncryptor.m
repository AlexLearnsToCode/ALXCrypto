//
//  ALXHMACEncryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXHMACEncryptor.h"
#import "ALXHashCryptoUtil.h"

@implementation ALXHMACEncryptor

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    const char *input = plaintext.UTF8String;
    
    ALXHashCryptoUtil *hmacUtil = [[ALXHashCryptoUtil alloc] initWithHmacEncryptor:self];
    if (!hmacUtil) {
        return @"";
    }
    
    const char *keyData = self.key.UTF8String;
    unsigned char result[hmacUtil.resultLength];
    
    CCHmac(hmacUtil.hmacAlgorithm, keyData, strlen(keyData), input, strlen(input), result);
    
    return [hmacUtil hashStringWithBytes:result];
}

@end
