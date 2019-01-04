//
//  ALXSymmetricEncryptor.m
//  ALXCrypto
//
//  Created by Alexgao on 2019/1/3.
//

#import "ALXSymmetricEncryptor.h"

@implementation ALXSymmetricEncryptor

- (NSString *)encrypt:(NSString *)plaintext{
    if (![super encrypt:plaintext].length) {
        return @"";
    }
    
    // TODO:Alexgao---处理 key/algorithm/padding 等
    if (!self.key.length) {
        NSAssert(self.key.length > 0, @"invalid argument 'key'.");
        return @"";
    }
    
    return plaintext;
}

@end
