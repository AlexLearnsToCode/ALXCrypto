//
//  ALXAsymmetricDecryptorUtil.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/4.
//

#import "ALXAsymmetricDecryptorUtil.h"
#import "ALXAsymmetricCryptor.h"

@implementation ALXAsymmetricDecryptorUtil

- (instancetype)initWithAsymmetricCryptor:(ALXAsymmetricCryptor *)asymmetricCryptor {
    self = [super init];
    if (self) {
        
        if (!asymmetricCryptor.privateKey.length && !asymmetricCryptor.privateKeyFilePath.length) {
            NSAssert(asymmetricCryptor.privateKey.length || asymmetricCryptor.privateKeyFilePath.length, @"invalid argument 'private key' or 'private key file path'.");
            return nil;
        } else {
            // 获取seckey
            if (asymmetricCryptor.privateKeyFilePath.length) {
                self.seckey = [self privateSecKeyFromContentsOfPrivateKey:asymmetricCryptor.privateKeyFilePath password:asymmetricCryptor.password];
            }
            if (asymmetricCryptor.privateKey.length) {
                self.seckey = [self privateSecKeyFromPrivateKey:asymmetricCryptor.privateKey];
            }
            
            if (self.seckey == nil) {
                NSAssert(self.seckey, @"can't access to seckey.");
                return nil;
            }
        }
    }
    return self;
}


#pragma mark - Private Key

- (SecKeyRef)privateSecKeyFromPrivateKey:(NSString *)privateKey{
    NSRange spos = [privateKey rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
    NSRange epos = [privateKey rangeOfString:@"-----END RSA PRIVATE KEY-----"];
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        privateKey = [privateKey substringWithRange:range];
    }
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    privateKey = [privateKey stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This will be base64 encoded, decode it.
    NSData *data = [[NSData alloc] initWithBase64EncodedString:privateKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [self stripPrivateKeyHeader:data];
    if(!data){
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PrivKey";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *privateKeyDic = [[NSMutableDictionary alloc] init];
    [privateKeyDic setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKeyDic setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [privateKeyDic setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)privateKeyDic);
    
    // Add persistent version of the key to system keychain
    [privateKeyDic setObject:data forKey:(__bridge id)kSecValueData];
    [privateKeyDic setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)
     kSecAttrKeyClass];
    [privateKeyDic setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)privateKeyDic, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [privateKeyDic removeObjectForKey:(__bridge id)kSecValueData];
    [privateKeyDic removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [privateKeyDic setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [privateKeyDic setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKeyDic, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}

- (NSData *)stripPrivateKeyHeader:(NSData *)d_key{
    // Skip ASN.1 private key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx     = 22; //magic byte at offset 22
    
    if (0x04 != c_key[idx++]) return nil;
    
    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    if (!det) {
        c_len = c_len & 0x7f;
    } else {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    
    // Now make a new NSData from this buffer
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}

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
