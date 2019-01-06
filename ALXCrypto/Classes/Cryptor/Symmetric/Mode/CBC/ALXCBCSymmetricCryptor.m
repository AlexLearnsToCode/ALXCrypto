//
//  ALXCBCSymmetricCryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXCBCSymmetricCryptor.h"
#import "ALXSymmetricCryptoUtil.h"

@implementation ALXCBCSymmetricCryptor

- (CCMode)mode{
    return kCCModeCBC;
}

- (NSString *)iv{
    if (!_iv.length) {
        return @"0000000000000000";
    }
    return _iv;
}

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    
    ALXSymmetricCryptoUtil *encryptorUtil = [[ALXSymmetricCryptoUtil alloc] initWithSymmetricCryptor:self];
    if (!encryptorUtil) {
        return @"";
    }
    encryptorUtil.operation = kCCEncrypt;
    plaintext = [encryptorUtil addPaddingToString:plaintext];
    
    NSData *contentData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = contentData.length;
    // 为结束符'\\0' +1
    char keyPtr[encryptorUtil.keySize + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [self.key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    // 密文长度 <= 明文长度 + BlockSize
    size_t encryptSize = dataLength + encryptorUtil.blockSize;
    void *encryptedBytes = malloc(encryptSize);
    size_t actualOutSize = 0;
    
    NSData *initVector = [self.iv dataUsingEncoding:NSUTF8StringEncoding];
    if (initVector.length != encryptorUtil.blockSize) {
        NSAssert(initVector.length == 16, @"invalid argument 'iv'");
        return @"";
    }
    
    CCCryptorStatus cryptStatus = CCCrypt(encryptorUtil.operation,
                                          encryptorUtil.algorithm,
                                          encryptorUtil.options,  // 系统默认使用 CBC，然后指明使用 PKCS7Padding
                                          keyPtr,
                                          encryptorUtil.keySize,
                                          initVector.bytes,
                                          contentData.bytes,
                                          dataLength,
                                          encryptedBytes,
                                          encryptSize,
                                          &actualOutSize);
    if (cryptStatus == kCCSuccess) {
        // 对加密后的数据进行 base64 编码
        return [[NSData dataWithBytesNoCopy:encryptedBytes length:actualOutSize] base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    }
    free(encryptedBytes);
    return @"";
}

- (NSString *)decrypt:(NSString *)ciphertext{
    if (![super decrypt:ciphertext].length) {
        return @"";
    }
    
    ALXSymmetricCryptoUtil *decryptorUtil = [[ALXSymmetricCryptoUtil alloc] initWithSymmetricCryptor:self];
    if (!decryptorUtil) {
        return @"";
    }
    decryptorUtil.operation = kCCDecrypt;
    ciphertext = [decryptorUtil removePaddingFromString:ciphertext];
    
    // 把 base64 String 转换成 Data
    NSData *contentData = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSUInteger dataLength = contentData.length;
    char keyPtr[decryptorUtil.keySize + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [self.key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    size_t decryptSize = dataLength + decryptorUtil.blockSize;
    void *decryptedBytes = malloc(decryptSize);
    size_t actualOutSize = 0;
    
    NSData *initVector = [self.iv dataUsingEncoding:NSUTF8StringEncoding];
    if (initVector.length != decryptorUtil.blockSize) {
        NSAssert(initVector.length == 16, @"invalid argument 'key'.");
        return @"";
    }
    
    CCCryptorStatus cryptStatus = CCCrypt(decryptorUtil.operation,
                                          decryptorUtil.algorithm,
                                          decryptorUtil.options,
                                          keyPtr,
                                          decryptorUtil.keySize,
                                          initVector.bytes,
                                          contentData.bytes,
                                          dataLength,
                                          decryptedBytes,
                                          decryptSize,
                                          &actualOutSize);
    if (cryptStatus == kCCSuccess) {
        return [[NSString alloc] initWithData:[NSData dataWithBytesNoCopy:decryptedBytes length:actualOutSize] encoding:NSUTF8StringEncoding];
    }
    free(decryptedBytes);
    return @"";
}

@end
