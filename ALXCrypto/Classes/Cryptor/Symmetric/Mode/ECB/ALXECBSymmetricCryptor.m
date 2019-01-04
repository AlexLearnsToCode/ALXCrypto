//
//  ALXECBSymmetricCryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXECBSymmetricCryptor.h"
#import "ALXSymmetricCryptoUtil.h"

@implementation ALXECBSymmetricCryptor

- (CCMode)mode{
    return kCCModeECB;
}

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    NSData* data = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    
    ALXSymmetricCryptoUtil *encryptorUtil = [[ALXSymmetricCryptoUtil alloc] initWithSymmetricCryptor:self];
    if (!encryptorUtil) {
        return @"";
    }
    encryptorUtil.operation = kCCEncrypt;
    
    // key
    char keyPtr[kCCKeySizeAES256+1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [self.key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    // result
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(encryptorUtil.operation,
                                          self.algorithm,
                                          encryptorUtil.options,
                                          keyPtr,
                                          [self.key length],
                                          NULL,
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

- (NSString *)decrypt:(NSString *)ciphertext{
    if (![super decrypt:ciphertext].length) {
        return @"";
    }
    NSData* data = [ciphertext dataUsingEncoding:NSUTF8StringEncoding];
    
    ALXSymmetricCryptoUtil *decryptorUtil = [[ALXSymmetricCryptoUtil alloc] initWithSymmetricCryptor:self];
    if (!decryptorUtil) {
        return @"";
    }
    decryptorUtil.operation = kCCDecrypt;
    
    // key
    char keyPtr[kCCKeySizeAES256+1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [self.key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    // result
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(decryptorUtil.operation,
                                          self.algorithm,
                                          decryptorUtil.options,
                                          keyPtr,
                                          [self.key length],
                                          NULL,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [decryptorUtil resultStringWithBytes:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return @"";
}

@end
