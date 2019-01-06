//
//  ALXHMACCryptoUtil.m
//  ALXCrypto
//
//  Created by 高昊 on 2019/1/6.
//

#import "ALXHMACCryptoUtil.h"
#import "ALXHMACCryptor.h"

static int ALXLengthFromHMACAlgorithm(ALXHMACAlgorithm algorithm) {
    switch (algorithm) {
        case ALXHMACAlgorithmmd5:{
            return CC_MD5_DIGEST_LENGTH;
        }
        case ALXHMACAlgorithmSHA1:{
            return CC_SHA1_DIGEST_LENGTH;
        }
        case ALXHMACAlgorithmSHA256:{
            return CC_SHA256_DIGEST_LENGTH;
        }
        case ALXHMACAlgorithmSHA512:{
            return CC_SHA384_DIGEST_LENGTH;
        }
        default:
            return -1;
    }
}

static CCHmacAlgorithm ALXHmacAlgorithmFromHashAlgorithm(ALXHMACAlgorithm algorithm) {
    switch (algorithm) {
        case ALXHMACAlgorithmmd5:{
            return kCCHmacAlgMD5;
        }
        case ALXHMACAlgorithmSHA1:{
            return kCCHmacAlgSHA1;
        }
        case ALXHMACAlgorithmSHA256:{
            return kCCHmacAlgSHA256;
        }
        case ALXHMACAlgorithmSHA512:{
            return kCCHmacAlgSHA512;
        }
        default:
            return kCCHmacAlgMD5;
    }
}

@implementation ALXHMACCryptoUtil

- (instancetype)initWithHMACCryptor:(ALXHMACCryptor *)hmacCryptor {
    self = [super init];
    if (self) {
        
        self.resultLength = ALXLengthFromHMACAlgorithm(hmacCryptor.algorithm);
        if (self.resultLength <= 0) {
            NSAssert(self.resultLength > 0, @"invalid argument 'algorithm'.");
            return nil;
        }
        
        self.hmacAlgorithm = ALXHmacAlgorithmFromHashAlgorithm(hmacCryptor.algorithm);
        
        if (!hmacCryptor.key.length) {
            NSAssert(hmacCryptor.key.length > 0, @"invalid argument 'key'.");
            return nil;
        }
    }
    return self;
}

- (NSString *)hmacStringWithBytes:(uint8_t *)result{
    NSMutableString *digest = [NSMutableString string];
    for (int i = 0; i < self.resultLength; i++) {
        [digest appendFormat:@"%02x", result[i]];
    }
    return [digest copy];
}

@end
