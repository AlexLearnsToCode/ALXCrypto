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
    ALXHMACCryptor *hmacCryptor = [ALXCryptorFactory hmacCryptorWithAlgorithm:ALXHMACAlgorithmSHA1 key:KEY];
    NSLog(@"hmac---%@", [hmacCryptor encrypt:TEST]);
}

- (void)testECB{
    
    NSLog(@"length---%d", [TEST dataUsingEncoding:NSUTF8StringEncoding].length);
    
    ALXECBSymmetricCryptor *ecbCryptor = [ALXCryptorFactory ecbSymmetricCryptorWithAlgorithm:ALXSymmetricCryptoAlgorithm3DES key:KEY padding:ALXPKCS7Padding];
    NSLog(@"ecb---encrypt---%@", [ecbCryptor encrypt:TEST]);

    NSLog(@"ecb---decrypt---%@", [ecbCryptor decrypt:[ecbCryptor encrypt:TEST]]);
}

- (void)testCBC{
    ALXCBCSymmetricCryptor *cbcCryptor = [ALXCryptorFactory cbcSymmetricCryptorWithAlgorithm:ALXSymmetricCryptoAlgorithm3DES key:KEY padding:ALXPKCSZeroPadding iv:IV];
    NSLog(@"cbc---encrypt---%@", [cbcCryptor encrypt:TEST]);
    
    NSLog(@"cbc---decrypt---%@", [cbcCryptor decrypt:[cbcCryptor encrypt:TEST]]);
}

- (void)testRSA{
    ALXRSAAsymmetricCryptor *rsaCryptor = [ALXCryptorFactory rsaAsymmetricCryptorWithPublicKey:@"" privateKey:@""];
    NSLog(@"rsa---encrypt---%@", [rsaCryptor encrypt:TEST]);
    
    NSLog(@"rsa---decrypt---%@", [rsaCryptor decrypt:[rsaCryptor encrypt:TEST]]);
}

@end
