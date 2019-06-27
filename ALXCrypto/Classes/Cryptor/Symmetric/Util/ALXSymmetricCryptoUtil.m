//
//  ALXSymmetricCryptoUtil.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXSymmetricCryptoUtil.h"
#import "ALXSymmetricCryptor.h"

static CCPadding ALXCCPaddingFromPadding(ALXPKCSPadding padding) {
    switch (padding) {
        case ALXPKCS7Padding:{
            return ccPKCS7Padding;
        }
        default:
            return ccNoPadding;
    }
}

static int ALXBlockSizeFromAlgorithm(ALXSymmetricCryptoAlgorithm algorithm){
    switch (algorithm) {
        case ALXSymmetricCryptoAlgorithmAES128:{
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
        
        
        self.padding = ALXCCPaddingFromPadding(symmetricCryptor.padding);
        
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
//        NSData *keyData = [symmetricCryptor.key dataUsingEncoding:NSUTF8StringEncoding];
//        if (keyData.length > self.keySize) {
//            NSAssert(keyData.length <= self.keySize, @"invalid key size.");
//            return nil;
//        }
    }
    return self;
}

- (NSString *)addPaddingToString:(NSString *)plaintext{
    
//    if (self.symmetricCryptor.padding == ALXPKCSNoPadding) {
//        if (plaintext.length % self.blockSize != 0) {
//            NSAssert(plaintext.length % self.blockSize == 0, @"");
//            return plaintext;
//        }
//    }
    
    switch (self.symmetricCryptor.padding) {
        case ALXPKCS7Padding:{
            return plaintext;
        }
        case ALXPKCSZeroPadding:{
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

- (NSString *)removePaddingFromString:(NSString *)plainText{
    switch (self.symmetricCryptor.padding) {
        case ALXPKCS7Padding:{
            return plainText;
        }
        case ALXPKCSZeroPadding:{
            const char *originalStr = [plainText UTF8String];
            int i = 0;
            while(originalStr[i] != '\0'){
                i++;
            }
            return [[NSString alloc] initWithBytes:originalStr length:i encoding:NSUTF8StringEncoding];
        }
        default:
            return plainText;
    }
}

@end
