//
//  ALXRSAAsymmetricEncryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXRSAAsymmetricEncryptor.h"
#import <Security/Security.h>
#import "ALXAsymmetricCryptoUtil.h"

@implementation ALXRSAAsymmetricEncryptor

- (ALXAsymmetricCryptoAlgorithm)algorithm{
    return ALXAsymmetricCryptoAlgorithmRSA;
}

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    
    ALXAsymmetricCryptoUtil *encryptorUtil = [[ALXAsymmetricCryptoUtil alloc] initWithAsymmetricEncryptor:self];
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

@end
