//
//  ALXRSAAsymmetricCryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXRSAAsymmetricCryptor.h"
#import <Security/Security.h>
#import "ALXAsymmetricEncryptorUtil.h"
#import "ALXAsymmetricDecryptorUtil.h"

@implementation ALXRSAAsymmetricCryptor

- (ALXAsymmetricCryptoAlgorithm)algorithm{
    return ALXAsymmetricCryptoAlgorithmRSA;
}

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    
    ALXAsymmetricEncryptorUtil *encryptorUtil = [[ALXAsymmetricEncryptorUtil alloc] initWithAsymmetricCryptor:self];
    if (!encryptorUtil) {
        return @"";
    }
    
    // TODO:Alexgao---公钥加密
    NSData *data = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(encryptorUtil.seckey) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(encryptorUtil.seckey,
                               kSecPaddingPKCS1,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            [ret appendBytes:outbuf length:outlen];
        }
    }
    
    free(outbuf);
    CFRelease(encryptorUtil.seckey);
    
    return [[NSString alloc] initWithData:[ret base64EncodedDataWithOptions:0] encoding:NSUTF8StringEncoding];;
}

- (NSString *)decrypt:(NSString *)ciphertext{
    if (![super decrypt:ciphertext].length) {
        return @"";
    }
    
    ALXAsymmetricDecryptorUtil *decryptorUtil = [[ALXAsymmetricDecryptorUtil alloc] initWithAsymmetricCryptor:self];
    if (!decryptorUtil) {
        return @"";
    }
    // TODO:Alexgao---私钥解密
    NSData *data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(decryptorUtil.seckey) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(decryptorUtil.seckey,
                               kSecPaddingNone,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            //the actual decrypted data is in the middle, locate it!
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for ( int i = 0; i < outlen; i++ ) {
                if ( outbuf[i] == 0 ) {
                    if ( idxFirstZero < 0 ) {
                        idxFirstZero = i;
                    } else {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            
            [ret appendBytes:&outbuf[idxFirstZero+1] length:idxNextZero-idxFirstZero-1];
        }
    }
    
    free(outbuf);
    CFRelease(decryptorUtil.seckey);
    return [[NSString alloc] initWithData:ret encoding:NSUTF8StringEncoding];
}

@end
