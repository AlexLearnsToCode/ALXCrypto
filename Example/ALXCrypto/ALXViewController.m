//
//  ALXViewController.m
//  ALXCrypto
//
//  Created by alexlearnstocode on 01/03/2019.
//  Copyright (c) 2019 alexlearnstocode. All rights reserved.
//

#import "ALXViewController.h"
#import <ALXCrypto/ALXCrypto.h>
#import "ALXCryptorFactory.h"

#define TEST @"aaaaaaaaaaaaaaaaaaaaaaaaaa"
#define KEY @"test"
#define IV @"aaaaaaaabbbbbbbbbbbbbb"

@interface ALXViewController ()

@end

@implementation ALXViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    // 测试通过
//    [self testHash];
    
    // 测试通过
//    [self testHmac];
    
    // 测试通过
//    [self testECB];
    
    // 测试通过
//    [self testCBC];
//    NSString *publicFilePath = [[NSBundle mainBundle] pathForResource:@"lagou" ofType:@"der"];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)testHash{
    ALXHashCryptor *hashCryptor = [ALXCryptorFactory hashCryptorWithAlgorithm:ALXHashAlgorithmSHA512];
    NSLog(@"hash---%@", [hashCryptor encrypt:TEST]);
}

- (void)testHmac{
    ALXHMACCryptor *hmacCryptor = [ALXCryptorFactory hmacCryptorWithAlgorithm:ALXHMACAlgorithmSHA1 key:KEY];
    NSLog(@"hmac---%@", [hmacCryptor encrypt:TEST]);
}

- (void)testECB{
    
    ALXECBSymmetricCryptor *ecbCryptor = [ALXCryptorFactory ecbSymmetricCryptorWithAlgorithm:ALXSymmetricCryptoAlgorithm3DES key:KEY padding:ALXPKCS7Padding];
    NSLog(@"ecb---encrypt---%@", [ecbCryptor encrypt:TEST]);

    NSLog(@"ecb---decrypt---%@", [ecbCryptor decrypt:[ecbCryptor encrypt:TEST]]);
}

- (void)testCBC{
    ALXCBCSymmetricCryptor *cbcCryptor = [ALXCryptorFactory cbcSymmetricCryptorWithAlgorithm:ALXSymmetricCryptoAlgorithm3DES key:KEY padding:ALXPKCSZeroPadding iv:IV];
    NSLog(@"cbc---encrypt---%@", [cbcCryptor encrypt:TEST]);
    
    NSLog(@"cbc---decrypt---%@", [cbcCryptor decrypt:[cbcCryptor encrypt:TEST]]);
}

- (void)testRSA_Encryption {
    ALXRSAAsymmetricCryptor *rsaCryptor = [ALXCryptorFactory rsaAsymmetricCryptorWithPublicKeyFilePath:@"" padding:ALXAsymmetricCryptoPaddingPKCS1];
    NSLog(@"rsa---encrypt---%@", [rsaCryptor encrypt:@""]);
}

- (void)testRSA_Decryption {
    ALXRSAAsymmetricCryptor *rsaCryptor = [ALXCryptorFactory rsaAsymmetricCryptorWithPrivateKeyFile:@"" padding:ALXAsymmetricCryptoPaddingPKCS1];
    NSLog(@"rsa---decrypt---%@", [rsaCryptor decrypt:@""]);
}

- (void)testRSA_Signature {
    ALXRSAAsymmetricCryptor *rsaCryptor = [ALXCryptorFactory rsaAsymmetricCryptorWithPrivateKeyFile:@""
                                                                                 signatureAlgorithm:ALXAsymmetricCryptoSignatureAlgorithmSHA1];
    NSLog(@"rsa---sign---%@", [rsaCryptor signWithRawString:@""]);
}

- (void)testRSA_VerifySignature {
    ALXRSAAsymmetricCryptor *rsaCryptor = [ALXCryptorFactory rsaAsymmetricCryptorWithPublicKeyFilePath:@""
                                                                                    signatureAlgorithm:ALXAsymmetricCryptoSignatureAlgorithmSHA1];
    NSLog(@"rsa---verifySign---%d", [rsaCryptor verifyWithSignedString:@""]);
}

@end
