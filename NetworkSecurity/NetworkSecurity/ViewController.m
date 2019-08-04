//
//  ViewController.m
//  NetworkSecurity
//
//  Created by 飞鱼 on 2019/7/26.
//  Copyright © 2019 rongzhixin. All rights reserved.
//

#import "ViewController.h"
#import "RSA.h"
#import "DES.h"
#import "AES.h"

#define kPublicKey @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+R9lHSrmOgrmfEKD4kMf4BK7RK12F1XogLt5buvE1Y6up9GBnTht4VBSgu+5Ns0Cp1I4wtVgY8olbddbiJzWux8cHKBAMj8P55Cc0tpgZhsMMm9MgkzT9zWiDAfM2ARqtKbpbU2lWCCI/LLjqBjq3/0xdNPpDvR8K7qLiDCcuFwIDAQAB"

#define kPrivateKey @"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALkUWLqzeWxIM+TTNFjsCKjejOJ5lS01SOEUH73RT25PdE6gxn4imtBPaZ9oVgmlx6XG5YiXfmMSLGMH2dEIfCEHl28evb9DNhC40v5Bu7coHd5ITo1GCCxMguBe3WRsYV1iutWl9tPZBz+LjMVqoE3CvXTB6L33Jg8nDCKknmu7AgMBAAECgYEAmFFWdNEgLS1/B+OKQWR/+/qsl/bX/szLnfGh7eZFKNPbNJq8wTJZlvbERpznsijtllGKtk93hLGANkBP0ujYvi/WXmL0qep+OCr7Houbo11Hcv8t7E1dJkIwI1ZKe01csy8bZdkFrtap3XZgLER1551vLtNsRNzErL4dkuTFRAECQQDeCPF/f2yPYQe89s9lxjYHxlylhdiihuhe3fSAh3EdVhq6XXEpc9tZbn5J98mXiwoh+y+ia7n4ibLyJzNq6scbAkEA1WQzFC3vOP7dziCjK5LcXbo6wCtMslg9UxJ6r0Mb+fN87MuPhkDdLTwCpBb7zXP7d6Rd3iAs4mQeOY2/mUYX4QJAapdUiGa90R89vcOm0S8UpSrfMz9MPsoRJ+naBRIAhZreffV56/KIrShUTGI+TxgapzGVLp4Uy3IfjAyxrHRFXQJAFwAt4UbyOhp+nfE2pUO3LQMdwgjow3Bva7zaLHn3UgHEvWFTnwzuyillv3oauhJ+UG8PDxo4vE4+U8XLmSHNAQJBAIebZmOOn8JwwfVJFEMvdUjMTrsIdxysWkwWfAyEnx5s6oPtl2z0n59OQbo3sNPFSXATD/VgO0IVnrx1/ac1hx0="

@interface ViewController ()

@property (nonatomic, copy) NSString *aesKey;

@property (nonatomic, copy) NSString *desKey;

@end

@implementation ViewController

- (NSString *)aesKey {
    if (!_aesKey) {
        unichar aesKey[16];
        for (int i = 0; i < 16; i++) {
            aesKey[i] = [kPublicKey characterAtIndex: arc4random()%128];
        }
        _aesKey = [NSString stringWithCharacters:aesKey length:16];
    }
    NSLog(@"aeskey:%@", _aesKey);
    return _aesKey;
}

- (NSString *)desKey {
    if (!_desKey) {
        unichar desKey[8];
        for (int i = 0; i < 8; i++) {
            desKey[i] = [kPublicKey characterAtIndex: arc4random()%128];
        }
        _desKey = [NSString stringWithCharacters:desKey length:8];
    }
    NSLog(@"deskey:%@", _desKey);
    return _desKey;
}

- (IBAction)sendRequest:(UIButton *)sender {
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
    NSURL *url = [NSURL URLWithString:@"http://192.168.0.199:8082/index"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.allHTTPHeaderFields = @{
                                    @"Content-Type":@"text/plain"
                                    };

    NSString *jsonStr = [NSString stringWithFormat:@"{\"aesKey\":\"%@\",\"desKey\":\"%@\"}", self.aesKey, self.desKey];
    NSData *data = [jsonStr dataUsingEncoding:NSUTF8StringEncoding];
    request.HTTPBody = [RSA encryptData:data publicKey:kPublicKey];
    NSLog(@"RSA Request: %@", jsonStr);
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        // 测试RSA，正常AES
        NSData *decodeData = [RSA decryptData:data privateKey:kPrivateKey];
        NSString *decodeStr = [[NSString alloc]initWithData:decodeData encoding:NSUTF8StringEncoding];
        NSLog(@"RSA Response: %@", decodeStr);
    }];
    [task resume];
}

- (IBAction)aesEncrypt:(UIButton *)sender {
    if (!_aesKey) {
        NSLog(@"aeskey 未生成， 请先生成AESKEY 传给后端 RSAEncrypte");
        return;
    }
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
    NSURL *url = [NSURL URLWithString:@"http://192.168.0.199:8082/aes"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.allHTTPHeaderFields = @{
                                    @"Content-Type":@"text/plain"
                                    };
    NSString *aesStr = @"aes send ok, 哈哈哈";
    NSData *data = [aesStr dataUsingEncoding:NSUTF8StringEncoding];
    request.HTTPBody = [AES encryptData:data key:_aesKey];
    NSLog(@"AES Request: %@", aesStr);
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        NSData *decodeData = [AES decryptData:data key: self->_aesKey];
        NSString *decodeStr = [[NSString alloc]initWithData:decodeData encoding:NSUTF8StringEncoding];
        NSLog(@"AES Response: %@", decodeStr);
    }];
    [task resume];
}

- (IBAction)desEncrypt:(UIButton *)sender {
    if (!_aesKey) {
        NSLog(@"deskey 未生成， 请先生成DESKEY 传给后端 RSAEncrypte");
        return;
    }
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
    NSURL *url = [NSURL URLWithString:@"http://192.168.0.199:8082/des"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.allHTTPHeaderFields = @{
                                    @"Content-Type":@"text/plain"
                                    };
    NSString *desStr = @"des send ok";
    NSLog(@"DES Request: %@", desStr);
    NSData *data = [desStr dataUsingEncoding:NSUTF8StringEncoding];
    request.HTTPBody = [DES encryptData:data key:_desKey];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        NSData *decodeData = [DES decryptData:data key: self->_desKey];
        NSString *decodeStr = [[NSString alloc]initWithData:decodeData encoding:NSUTF8StringEncoding];
        NSLog(@"DES Response: %@", decodeStr);
    }];
    [task resume];
}

@end
