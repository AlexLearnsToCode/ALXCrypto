//
//  ALXRSAAsymmetricCryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXRSAAsymmetricCryptor.h"
#import <Security/Security.h>
#import "ALXAsymmetricCryptoUtil.h"
#import "ALXAsymmetricSignatureUtil.h"

@implementation ALXRSAAsymmetricCryptor

- (ALXAsymmetricCryptoAlgorithm)algorithm{
    return ALXAsymmetricCryptoAlgorithmRSA;
}

#pragma mark - Encryption

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    
    ALXAsymmetricCryptoUtil *cryptoUtil = [[ALXAsymmetricCryptoUtil alloc] initWithAsymmetricCryptor:self];
    if (!cryptoUtil || !cryptoUtil.publicSecKey) {
        NSAssert(!cryptoUtil || !cryptoUtil.publicSecKey, @"invalid cryptoUtil.");
        return @"";
    }
    
    NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    if (plainData.length > cryptoUtil.maxPlainTextSize) {
        NSAssert(plainData.length > cryptoUtil.maxPlainTextSize, @"Plain Text is too long.");
        return @"";
    }
    
    NSData *cipherData = nil;
    size_t resultDataSize = 256;
    uint8_t *resultData = malloc(resultDataSize);
    bzero(resultData, resultDataSize);
    
    int result = SecKeyEncrypt(cryptoUtil.publicSecKey,
                               cryptoUtil.secPadding,
                               plainData.bytes,
                               plainData.length,
                               resultData,
                               &resultDataSize);
    if (result == errSecSuccess) {
        cipherData = [NSData dataWithBytes:resultData length:resultDataSize];
    }
    free(resultData);
    resultData = NULL;
    
    return [cipherData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
}

- (NSString *)decrypt:(NSString *)ciphertext{
    if (![super decrypt:ciphertext].length) {
        return @"";
    }
    
    ALXAsymmetricCryptoUtil *cryptoUtil = [[ALXAsymmetricCryptoUtil alloc] initWithAsymmetricCryptor:self];
    if (!cryptoUtil || !cryptoUtil.privateSecKey) {
        NSAssert(!cryptoUtil || !cryptoUtil.privateSecKey, @"invalid cryptoUtil.");
        return @"";
    }
    
    NSData *cipherData = [ciphertext dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *plainData = nil;
    size_t resultDataSize = cryptoUtil.maxPlainTextSize;
    uint8_t *resultData = malloc(resultDataSize);
    bzero(resultData, resultDataSize);
    
    int result = SecKeyEncrypt(cryptoUtil.privateSecKey,
                               cryptoUtil.secPadding,
                               cipherData.bytes,
                               cipherData.length,
                               resultData,
                               &resultDataSize);
    if (result == errSecSuccess) {
        plainData = [NSData dataWithBytes:resultData length:resultDataSize];
    }
    free(resultData);
    resultData = NULL;
    
    return [plainData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
}

#pragma mark - Signature

- (NSString *)signWithRawString:(NSString *)rawString {
    if (![super signWithRawString:rawString].length) {
        return @"";
    }
    
    ALXAsymmetricCryptoUtil *cryptoUtil = [[ALXAsymmetricCryptoUtil alloc] initWithAsymmetricCryptor:self];
    if (!cryptoUtil || !cryptoUtil.privateSecKey) {
        NSAssert(!cryptoUtil || !cryptoUtil.privateSecKey, @"invalid cryptoUtil.");
        return @"";
    }
    
    ALXAsymmetricSignatureUtil *signatureUtil = [[ALXAsymmetricSignatureUtil alloc] initWithAsymmetricCryptor:self];
    
    NSData *rawData = [rawString dataUsingEncoding:NSUTF8StringEncoding];
    
    OSStatus ret;
    NSData *signatureData = nil;
    size_t resultLength = SecKeyGetBlockSize(cryptoUtil.privateSecKey);
    uint8_t *result = malloc(resultLength);
    bzero(result, resultLength);
    
    ret = SecKeyRawSign(cryptoUtil.privateSecKey, signatureUtil.secPadding, rawData.bytes, rawData.length, result, &resultLength);
    if (ret == errSecSuccess) {
        signatureData = [NSData dataWithBytes:result length:resultLength];
    }
    
    free(result);
    result = NULL;
    
    return [signatureData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
}

- (BOOL)verifyWithSignedString:(NSString *)signedString rawString:(NSString *)rawString{
    if (![super verifyWithSignedString:signedString]) {
        return NO;
    }
    
    ALXAsymmetricCryptoUtil *cryptoUtil = [[ALXAsymmetricCryptoUtil alloc] initWithAsymmetricCryptor:self];
    if (!cryptoUtil || !cryptoUtil.publicSecKey) {
        NSAssert(!cryptoUtil || !cryptoUtil.publicSecKey, @"invalid cryptoUtil.");
        return NO;
    }
    
    ALXAsymmetricSignatureUtil *signatureUtil = [[ALXAsymmetricSignatureUtil alloc] initWithAsymmetricCryptor:self];
    
    NSData *rawData = [rawString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signedData = [signedString dataUsingEncoding:NSUTF8StringEncoding];
    OSStatus ret = SecKeyRawVerify(cryptoUtil.publicSecKey, signatureUtil.secPadding, rawData.bytes, rawData.length,signedData.bytes, signedData.length);
    
    return ret == errSecSuccess;
}

@end
