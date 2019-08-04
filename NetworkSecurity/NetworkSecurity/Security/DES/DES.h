//
//  DES.h
//  NetworkSecurity
//
//  Created by 飞鱼 on 2019/7/27.
//  Copyright © 2019 rongzhixin. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DES : NSObject

//加密
+(NSString *)encryptString:(NSString *)plainText key:(NSString *)key;
//解密
+(NSString *)decryptString:(NSString *)plainText key:(NSString *)key;

+ (NSData *)encryptData:(NSData *)data key:(NSString *)key;

+ (NSData *)decryptData:(NSData *)data key:(NSString *)key;

@end

NS_ASSUME_NONNULL_END
