//
//  AES.h
//  NetworkSecurity
//
//  Created by 飞鱼 on 2019/7/27.
//  Copyright © 2019 rongzhixin. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AES : NSObject

//加密
+(NSData *)encryptData:(NSData *)data key:(NSString *)key;
//解密
+(NSData *)decryptData:(NSData *)data key:(NSString *)key;

@end

