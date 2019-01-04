//
//  ALXAsymmetricEncryptorUtil.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXAsymmetricEncryptorUtil.h"
#import "ALXAsymmetricCryptor.h"

@implementation ALXAsymmetricEncryptorUtil

- (instancetype)initWithAsymmetricCryptor:(ALXAsymmetricCryptor *)asymmetricCryptor {
    self = [super init];
    if (self) {
        
        if (!asymmetricCryptor.publicKey.length && !asymmetricCryptor.publicKeyFilePath.length) {
            NSAssert(asymmetricCryptor.publicKey.length || asymmetricCryptor.publicKeyFilePath.length, @"invalid argument 'public key' or 'public key file path'.");
            return nil;
        } else {
            // 获取seckey
            if (asymmetricCryptor.publicKeyFilePath.length) {
                self.seckey = [self publicKeyFromContentsOfPublicKey:asymmetricCryptor.publicKeyFilePath];
            }
            if (asymmetricCryptor.publicKey.length) {
                self.seckey = [self publicKeyFromPublicKey:asymmetricCryptor.publicKey];
            }
            
            if (self.seckey == nil) {
                NSAssert(self.seckey, @"can't access seckey.");
                return nil;
            }
        }
    }
    return self;
}

#pragma mark - Public Key

- (SecKeyRef)publicKeyFromPublicKey:(NSString *)publicKey{
    NSRange spos = [publicKey rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange epos = [publicKey rangeOfString:@"-----END PUBLIC KEY-----"];
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        publicKey = [publicKey substringWithRange:range];
    }
    publicKey = [publicKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    publicKey = [publicKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    publicKey = [publicKey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    publicKey = [publicKey stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This will be base64 encoded, decode it.
    NSData *data = [[NSData alloc] initWithBase64EncodedString:publicKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [self stripPublicKeyHeader:data];
    if(!data){
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PubKey";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKeyDic = [[NSMutableDictionary alloc] init];
    [publicKeyDic setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKeyDic setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKeyDic setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKeyDic);
    
    // Add persistent version of the key to system keychain
    [publicKeyDic setObject:data forKey:(__bridge id)kSecValueData];
    [publicKeyDic setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
     kSecAttrKeyClass];
    [publicKeyDic setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKeyDic, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [publicKeyDic removeObjectForKey:(__bridge id)kSecValueData];
    [publicKeyDic removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKeyDic setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKeyDic setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKeyDic, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}

- (NSData *)stripPublicKeyHeader:(NSData *)d_key{
    // Skip ASN.1 public key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx     = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return ([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

- (SecKeyRef)publicKeyFromContentsOfPublicKey:(NSString *)publicKeyFilePath{
    NSData *certData = [NSData dataWithContentsOfFile:publicKeyFilePath];
    if (!certData) {
        return nil;
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

@end
