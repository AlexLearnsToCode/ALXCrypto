//
//  ALXHashCryptoUtil.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXHashCryptoUtil.h"
#import "ALXHashCryptor.h"
#import "ALXHMACCryptor.h"

static int ALXLengthFromHashAlgorithm(ALXHashAlgorithm algorithm) {
    switch (algorithm) {
        case ALXHashAlgorithmmd516:
        case ALXHashAlgorithmMD516:{
            return CC_MD5_DIGEST_LENGTH;
        }
        case ALXHashAlgorithmmd532:
        case ALXHashAlgorithmMD532:{
            return CC_MD5_DIGEST_LENGTH * 2;
        }
        case ALXHashAlgorithmSHA1:{
            return CC_SHA1_DIGEST_LENGTH;
        }
        case ALXHashAlgorithmSHA256:{
            return CC_SHA256_DIGEST_LENGTH;
        }
        case ALXHashAlgorithmSHA384:{
            return CC_SHA384_DIGEST_LENGTH;
        }
        case ALXHashAlgorithmSHA512:{
            return CC_SHA512_DIGEST_LENGTH;
        }
        case ALXHashAlgorithmSHA224:{
            return CC_SHA224_DIGEST_LENGTH;
        }
        default:
            return -1;
    }
}

static BOOL ALXUppercaseFromHashAlgorithm(ALXHashAlgorithm algorithm) {
    switch (algorithm) {
        case ALXHashAlgorithmMD516:
        case ALXHashAlgorithmMD532:{
            return YES;
        }
        default:
            return NO;
    }
}

static CCHmacAlgorithm ALXHmacAlgorithmFromHashAlgorithm(ALXHashAlgorithm algorithm) {
    switch (algorithm) {
        case ALXHashAlgorithmmd516:
        case ALXHashAlgorithmMD516:
        case ALXHashAlgorithmmd532:
        case ALXHashAlgorithmMD532:{
            return kCCHmacAlgMD5;
        }
        case ALXHashAlgorithmSHA1:{
            return kCCHmacAlgSHA1;
        }
        case ALXHashAlgorithmSHA256:{
            return kCCHmacAlgSHA256;
        }
        case ALXHashAlgorithmSHA384:{
            return kCCHmacAlgSHA384;
        }
        case ALXHashAlgorithmSHA512:{
            return kCCHmacAlgSHA512;
        }
        case ALXHashAlgorithmSHA224:{
            return kCCHmacAlgSHA224;
        }
    }
}

@implementation ALXHashCryptoUtil

- (NSString *)hashStringWithBytes:(uint8_t *)result{
    NSMutableString *digest = [NSMutableString string];
    for (int i = 0; i < self.resultLength; i++) {
        if (self.uppercase) {
            [digest appendFormat:@"%02X", result[i]];
        } else {
            [digest appendFormat:@"%02x", result[i]];
        }
    }
    return [digest copy];
}

- (instancetype)initWithHashCryptor:(ALXHashCryptor *)hashCryptor {
    self = [super init];
    if (self) {
        
        self.resultLength = ALXLengthFromHashAlgorithm(hashCryptor.algorithm);
        if (self.resultLength <= 0) {
            NSAssert(self.resultLength > 0, @"invalid argument 'algorithm'.");
            return nil;
        }
        
        self.uppercase = ALXUppercaseFromHashAlgorithm(hashCryptor.algorithm);
        
        if ([hashCryptor isKindOfClass:[ALXHMACCryptor class]]) {
            ALXHMACCryptor *hmacCryptor = (ALXHMACCryptor *)hashCryptor;
            
            self.hmacAlgorithm = ALXHmacAlgorithmFromHashAlgorithm(hmacCryptor.algorithm);
            
            if (!hmacCryptor.key.length) {
                NSAssert(hmacCryptor.key.length > 0, @"invalid argument 'key'.");
                return nil;
            }
        }
    }
    return self;
}

@end
