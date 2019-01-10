//
//  ALXSymmetricCryptoUtil.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXSymmetricCryptoUtil.h"
#import "ALXSymmetricCryptor.h"

static CCOptions ALXOptionsFromModeAndPadding(CCMode mode, ALXPKCSPadding padding) {
    if (mode == kCCModeECB) {
        switch (padding) {
            case ALXPKCSNoPadding:{
                return 0x0000 | kCCModeECB;
            }
            case ALXPKCS7Padding:{
                return kCCOptionPKCS7Padding | kCCModeECB;
            }
            default:
                return kCCOptionPKCS7Padding | kCCModeECB;
        }
    } else if (mode == kCCModeCBC) {
        switch (padding) {
            case ALXPKCSNoPadding:{
                return 0x0000;
            }
            case ALXPKCS7Padding:{
                return kCCOptionPKCS7Padding;
            }
            default:
                return kCCOptionPKCS7Padding;
        }
    }
    return kCCOptionPKCS7Padding;
}

static int ALXBlockSizeFromAlgorithm(ALXSymmetricCryptoAlgorithm algorithm){
    switch (algorithm) {
        case ALXSymmetricCryptoAlgorithmAES128:
        case ALXSymmetricCryptoAlgorithmAES192:
        case ALXSymmetricCryptoAlgorithmAES256:{
            return kCCBlockSizeAES128;
        }
        case ALXSymmetricCryptoAlgorithmDES:{
            return kCCBlockSizeDES;
        }
        case ALXSymmetricCryptoAlgorithm3DES:{
            return kCCBlockSize3DES;
        }
            
        default:
            return -1;
            break;
    }
}

static int ALXKeySizeFromAlgorithm(ALXSymmetricCryptoAlgorithm algorithm){
    switch (algorithm) {
        case ALXSymmetricCryptoAlgorithmAES128:{
            return kCCKeySizeAES128;
        }
        case ALXSymmetricCryptoAlgorithmAES192:{
            return kCCKeySizeAES192;
        }
        case ALXSymmetricCryptoAlgorithmAES256:{
            return kCCKeySizeAES256;
        }
        case ALXSymmetricCryptoAlgorithmDES:{
            return kCCKeySizeDES;
        }
        case ALXSymmetricCryptoAlgorithm3DES:{
            return kCCKeySize3DES;
        }
        default:
            return -1;
    }
}

static CCAlgorithm ALXCCAlgorithmFromAlgorithm(ALXSymmetricCryptoAlgorithm algorithm){
    switch (algorithm) {
        case ALXSymmetricCryptoAlgorithmAES128:
        case ALXSymmetricCryptoAlgorithmAES192:
        case ALXSymmetricCryptoAlgorithmAES256:{
            return kCCAlgorithmAES;
        }
        case ALXSymmetricCryptoAlgorithmDES:{
            return kCCAlgorithmDES;
        }
        case ALXSymmetricCryptoAlgorithm3DES:{
            return kCCAlgorithm3DES;
        }
        default:
            return -1;
    }
}

@interface ALXSymmetricCryptoUtil ()

@property (nonatomic, weak) ALXSymmetricCryptor *symmetricCryptor;

@end

@implementation ALXSymmetricCryptoUtil

- (NSString *)resultStringWithBytes:(void *)result length:(size_t)length{
    // Alexgao---resultData会自动释放buffer
    NSData *resultData = [NSData dataWithBytesNoCopy:result length:length];
    if (self.operation == kCCEncrypt) {
        return [[NSString alloc] initWithData:[resultData base64EncodedDataWithOptions:NSDataBase64Encoding64CharacterLineLength] encoding:NSUTF8StringEncoding];
    }else if (self.operation == kCCDecrypt) {
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    return @"";
}

- (instancetype)initWithSymmetricCryptor:(ALXSymmetricCryptor *)symmetricCryptor {
    self = [super init];
    if (self) {
        
        self.symmetricCryptor = symmetricCryptor;
        
        self.options = ALXOptionsFromModeAndPadding(symmetricCryptor.mode, symmetricCryptor.padding);
        
        self.algorithm = ALXCCAlgorithmFromAlgorithm(symmetricCryptor.algorithm);
        if (self.algorithm < 0) {
            return nil;
        }
        
        self.blockSize = ALXBlockSizeFromAlgorithm(symmetricCryptor.algorithm);
        if (self.blockSize < 0) {
            return nil;
        }
        
        self.keySize = ALXKeySizeFromAlgorithm(symmetricCryptor.algorithm);
        if (self.keySize < 0) {
            return nil;
        }
        
        // TODO:Alexgao---keysize不匹配时,如何处理
//        NSUInteger keyBytesLength = [symmetricCryptor.key dataUsingEncoding:NSUTF8StringEncoding].length;
//        if (self.keySize != keyBytesLength) {
//            NSAssert(self.keySize == keyBytesLength, @"invalid argument 'key'");
//            return nil;
//        }
    }
    return self;
}

- (NSString *)addPaddingToString:(NSString *)plaintext{
    switch (self.symmetricCryptor.padding) {
        case ALXPKCS7Padding:{
            return plaintext;
        }
        case ALXPKCSNoPadding:{
            NSMutableData *data = [[plaintext dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
            int diff = self.blockSize - (data.length % self.blockSize);
            int padding = 0x00;
            for(int i = 0; i < diff; i++){
                [data appendBytes:&padding length:1];
            }
            return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        }
        default:
            return plaintext;
    }
}

- (NSString *)removePaddingFromString:(NSString *)ciphertext{
    switch (self.symmetricCryptor.padding) {
        case ALXPKCS7Padding:{
            return ciphertext;
        }
        case ALXPKCSNoPadding:{
            const char *originalStr = [ciphertext UTF8String];
            int i = 0;
            while( originalStr[i] != '\0' ){
                i++;
            }
            return [[NSString alloc] initWithBytes:originalStr length:i encoding:NSUTF8StringEncoding];
        }
        default:
            return ciphertext;
    }
}

@end
