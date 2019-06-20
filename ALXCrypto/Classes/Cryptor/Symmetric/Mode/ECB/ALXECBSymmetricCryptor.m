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
    
    ALXSymmetricCryptoUtil *encryptorUtil = [[ALXSymmetricCryptoUtil alloc] initWithSymmetricCryptor:self];
    if (!encryptorUtil) {
        return @"";
    }
    encryptorUtil.operation = kCCEncrypt;
    
    // 填充明文
    plaintext = [encryptorUtil addPaddingToString:plaintext];
    
    NSData *contentData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = contentData.length;
    
    // key
    NSMutableData *keyData = [self.key dataUsingEncoding:NSUTF8StringEncoding].mutableCopy;
    keyData.length = encryptorUtil.keySize;
    
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = kCCSuccess;
    status = CCCryptorCreateWithMode(encryptorUtil.operation, self.mode, encryptorUtil.algorithm, encryptorUtil.padding, NULL, keyData.bytes, keyData.length, NULL, 0, 0, kCCModeOptionCTR_BE, &cryptor);
    if (status != kCCSuccess) {
        NSAssert(status == kCCSuccess, @"cryptor create failed.");
        return @"";
    }

    //确定处理给定输入所需的输出缓冲区大小尺寸。
    size_t bufsize = CCCryptorGetOutputLength(cryptor, (size_t)dataLength, true);
    void * buf = malloc( bufsize );
    size_t bufused = 0;
    size_t bytesTotal = 0;
    
    //处理（加密，解密）一些数据。如果有结果的话,写入提供的缓冲区.
    status = CCCryptorUpdate(cryptor, [contentData bytes], (size_t)dataLength,
                             buf, bufsize, &bufused );
    if (status != kCCSuccess) {
        free(buf);
        NSAssert(status == kCCSuccess, @"cryptor update failed.");
        return @"";
    }
    
    bytesTotal += bufused;
    
    if (self.padding == ALXPKCS7Padding) {
        status = CCCryptorFinal(cryptor, buf + bufused, bufsize - bufused, &bufused);
        if (status != kCCSuccess) {
            free( buf );
            NSAssert(status == kCCSuccess, @"cryptor final failed.");
            return @"";
        }
        
        bytesTotal += bufused;
    }

    // 对加密后的数据进行 base64 编码
    NSString *cipherText = [[NSData dataWithBytesNoCopy:buf length:bytesTotal] base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    
    CCCryptorRelease( cryptor );
    
    return cipherText;
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
    
    // 把 base64 String 转换成 Data
    NSData *contentData = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSUInteger dataLength = contentData.length;
    
    // key
    NSMutableData *keyData = [self.key dataUsingEncoding:NSUTF8StringEncoding].mutableCopy;
    keyData.length = decryptorUtil.keySize;
    
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = kCCSuccess;
    status = CCCryptorCreateWithMode(decryptorUtil.operation, self.mode, decryptorUtil.algorithm, decryptorUtil.padding, NULL, keyData.bytes, keyData.length, NULL, 0, 0, kCCModeOptionCTR_BE, &cryptor);
    if (status != kCCSuccess) {
        NSAssert(status == kCCSuccess, @"cryptor create failed.");
        return @"";
    }
    
    //确定处理给定输入所需的输出缓冲区大小尺寸。
    size_t bufsize = CCCryptorGetOutputLength(cryptor, (size_t)dataLength, true);
    void * buf = malloc( bufsize );
    size_t bufused = 0;
    size_t bytesTotal = 0;
    
    //处理（加密，解密）一些数据。如果有结果的话,写入提供的缓冲区.
    status = CCCryptorUpdate(cryptor, [contentData bytes], (size_t)dataLength,
                             buf, bufsize, &bufused );
    if (status != kCCSuccess) {
        free(buf);
        NSAssert(status == kCCSuccess, @"cryptor update failed.");
        return @"";
    }
    
    bytesTotal += bufused;
    
    if (self.padding == ALXPKCS7Padding) {
        status = CCCryptorFinal(cryptor, buf + bufused, bufsize - bufused, &bufused);
        if (status != kCCSuccess) {
            free( buf );
            NSAssert(status == kCCSuccess, @"cryptor final failed.");
            return @"";
        }
        
        bytesTotal += bufused;
    }
    
    NSString *plainText = [[NSString alloc] initWithData:[NSData dataWithBytesNoCopy:buf length:bytesTotal] encoding:NSUTF8StringEncoding];
    
    // 移除填充
    plainText = [decryptorUtil removePaddingFromString:plainText];
    
    CCCryptorRelease( cryptor );
    
    return plainText;
}

@end
