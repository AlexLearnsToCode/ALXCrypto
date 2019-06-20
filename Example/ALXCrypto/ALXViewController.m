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

#define TEST @"中文中文"
#define KEY @"tessssssssssssws"
#define IV @"A-16"

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
    
    
//    [self testECB];
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
    
    ALXECBSymmetricCryptor *ecbCryptor = [ALXCryptorFactory ecbSymmetricCryptorWithAlgorithm:ALXSymmetricCryptoAlgorithmDES key:KEY padding:ALXPKCSZeroPadding];
    NSLog(@"ecb---encrypt---%@", [ecbCryptor encrypt:TEST]);

    NSLog(@"ecb---decrypt---%@", [ecbCryptor decrypt:[ecbCryptor encrypt:TEST]]);
}

- (void)testCBC{
    ALXCBCSymmetricCryptor *cbcCryptor = [ALXCryptorFactory cbcSymmetricCryptorWithAlgorithm:ALXSymmetricCryptoAlgorithmDES key:KEY padding:ALXPKCS7Padding iv:IV];
    NSLog(@"cbc---encrypt---%@", [cbcCryptor encrypt:TEST]);
    
    NSLog(@"cbc---decrypt---%@", [cbcCryptor decrypt:[cbcCryptor encrypt:TEST]]);
}

- (void)testRSA{
    ALXRSAAsymmetricCryptor *rsaCryptor = [ALXCryptorFactory rsaAsymmetricCryptorWithPublicKey:@"" privateKey:@""];
    NSLog(@"rsa---encrypt---%@", [rsaCryptor encrypt:TEST]);
    
    NSLog(@"rsa---decrypt---%@", [rsaCryptor decrypt:[rsaCryptor encrypt:TEST]]);
}

@end
