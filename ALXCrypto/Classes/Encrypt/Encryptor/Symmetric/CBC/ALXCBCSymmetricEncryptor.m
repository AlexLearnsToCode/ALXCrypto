//
//  ALXCBCSymmetricEncryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXCBCSymmetricEncryptor.h"
#import "ALXSymmetricCryptoUtil.h"

@implementation ALXCBCSymmetricEncryptor

- (CCMode)mode{
    return kCCModeCBC;
}

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    NSData* data = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    
    ALXSymmetricCryptoUtil *encryptorUtil = [[ALXSymmetricCryptoUtil alloc] initWithSymmetricEncryptor:self];
    if (!encryptorUtil) {
        return @"";
    }
    
    // key
    char keyPtr[kCCKeySizeAES256+1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [self.key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    // TODO:Alexgao---处理iv(暂时不知道iv为空的话怎么取默认值)
    // iv
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [self.iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    // result
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(encryptorUtil.operation,
                                          self.algorithm,
                                          encryptorUtil.options,
                                          keyPtr,
                                          [self.key length],
                                          ivPtr,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [encryptorUtil resultStringWithBytes:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return @"";
}



@end
