//
//  ALXAsymmetricCryptoUtil.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/7/4.
//

#import "ALXAsymmetricCryptoUtil.h"
#import "ALXAsymmetricCryptor.h"

static size_t ALXAsymmetricMaxBlockSizeFromPublicKeyAndPadding(SecKeyRef publicSecKey, ALXAsymmetricCryptoPadding padding) {
    size_t blockSize = SecKeyGetBlockSize(publicSecKey);
    if (padding == ALXAsymmetricCryptoPaddingPKCS1) {
        return blockSize - 11;
    }
    if (padding == ALXAsymmetricCryptoPaddingOAEP) {
        return blockSize - 42;
    }
    return blockSize;
}

static SecPadding ALXAsymmetricSecPaddingFromPadding(ALXAsymmetricCryptoPadding padding) {
    if (padding == ALXAsymmetricCryptoPaddingPKCS1) {
        return kSecPaddingPKCS1;
    }
    if (padding == ALXAsymmetricCryptoPaddingOAEP) {
        return kSecPaddingOAEP;
    }
    return kSecPaddingNone;
}

@implementation ALXAsymmetricCryptoUtil

- (instancetype)initWithAsymmetricCryptor:(ALXAsymmetricCryptor *)asymmetricCryptor {
    self = [super init];
    if (self) {
        
        if (!asymmetricCryptor.publicKeyFilePath.length && !asymmetricCryptor.privateKeyFilePath.length) {
            NSAssert(!asymmetricCryptor.publicKeyFilePath.length && !asymmetricCryptor.privateKeyFilePath.length, @"invalid argument 'publicKeyFilePath' or 'privateKeyFilePath'.");
            return nil;
        }
        
        // 获取公钥
        self.publicSecKey = [self publicKeyFromContentsOfPublicKey:asymmetricCryptor.publicKeyFilePath];
        self.blockSize = SecKeyGetBlockSize(self.publicSecKey);
        self.maxPlainTextSize = ALXAsymmetricMaxBlockSizeFromPublicKeyAndPadding(self.publicSecKey, asymmetricCryptor.padding);
        
        self.secPadding = ALXAsymmetricSecPaddingFromPadding(asymmetricCryptor.padding);
        
        // 获取私钥
        self.privateSecKey = [self privateSecKeyFromContentsOfPrivateKey:asymmetricCryptor.privateKeyFilePath password:asymmetricCryptor.password];
    }
    return self;
}

- (void)dealloc {
    CFRelease(self.publicSecKey);
    CFRelease(self.privateSecKey);
}

#pragma mark - Public Key

- (SecKeyRef)publicKeyFromContentsOfPublicKey:(NSString *)publicKeyFilePath{
    
    /*
     1. certificate
     2. trust
     3. public key
     */
    NSData *certData = [NSData dataWithContentsOfFile:publicKeyFilePath];
    if (!certData) {
        NSAssert(certData != nil, @"invalid publicKeyFilePath");
        return NULL;
    }
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (CFDataRef)certData);
    SecKeyRef key = NULL;
    SecTrustRef trust = NULL;
    SecPolicyRef policy = NULL;
    if (cert != NULL) {
        policy = SecPolicyCreateBasicX509();
        if (policy) {
            if (SecTrustCreateWithCertificates((CFTypeRef)cert, policy, &trust) == noErr) {
                SecTrustResultType result;
                if (SecTrustEvaluate(trust, &result) == noErr) {
                    key = SecTrustCopyPublicKey(trust);
                }
            }
        }
    }
    if (policy) CFRelease(policy);
    if (trust) CFRelease(trust);
    if (cert) CFRelease(cert);
    return key;
}

#pragma mark - Private Key

- (SecKeyRef)privateSecKeyFromContentsOfPrivateKey:(NSString *)privateKeyFilePath password:(NSString *)password{
    NSData *p12Data = [NSData dataWithContentsOfFile:privateKeyFilePath];
    if (!p12Data) {
        return nil;
    }
    SecKeyRef privateKeyRef = NULL;
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    [options setObject:password forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef) p12Data, (__bridge CFDictionaryRef)options, &items);
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    
    return privateKeyRef;
}

@end
