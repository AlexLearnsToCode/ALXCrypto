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

#define TEST @"IAmThePlainText"
#define KEY @"16BytesLengthKey"
#define IV @"A-16-Byte-String"

@interface ALXViewController ()

@end

@implementation ALXViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    
//    [self testHash];
//    [self testHmac];
    [self testECB];
    [self testCBC];
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
    ALXHMACCryptor *hmacCryptor = [ALXCryptorFactory hmacCryptorWithAlgorithm:ALXHMACAlgorithmmd5 key:KEY];
    NSLog(@"hmac---%@", [hmacCryptor encrypt:TEST]);
}

- (void)testECB{
    ALXECBSymmetricCryptor *ecbCryptor = [ALXCryptorFactory ecbSymmetricCryptorWithAlgorithm:ALXSymmetricCryptoAlgorithmAES192 key:KEY padding:ALXPKCS7Padding];
    NSLog(@"ecb---encrypt---%@", [ecbCryptor encrypt:TEST]);

    NSLog(@"ecb---decrypt---%@", [ecbCryptor decrypt:[ecbCryptor encrypt:TEST]]);
}

- (void)testCBC{
    ALXCBCSymmetricCryptor *cbcCryptor = [ALXCryptorFactory cbcSymmetricCryptorWithAlgorithm:ALXSymmetricCryptoAlgorithmAES192 key:KEY padding:ALXPKCS7Padding iv:IV];
    NSLog(@"cbc---encrypt---%@", [cbcCryptor encrypt:TEST]);
    
    NSLog(@"cbc---decrypt---%@", [cbcCryptor decrypt:[cbcCryptor encrypt:TEST]]);
}

- (void)testRSA{
    ALXRSAAsymmetricCryptor *rsaCryptor = [ALXCryptorFactory rsaAsymmetricCryptorWithPublicKey:@"" privateKey:@""];
    NSLog(@"rsa---encrypt---%@", [rsaCryptor encrypt:TEST]);
    
    NSLog(@"rsa---decrypt---%@", [rsaCryptor decrypt:[rsaCryptor encrypt:TEST]]);
}

@end
