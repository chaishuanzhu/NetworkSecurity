/*
 @author: ideawu
 @link: https://github.com/ideawu/Objective-C-RSA
 @RSASign: https://github.com/Larrywanglong/RSAAndSignatureDemo Alipay openssl
*/

#import <Foundation/Foundation.h>

@interface RSA : NSObject

/**
 *  加密方法
 *
 *  @param str   需要加密的字符串
 *  @param path  '.der'格式的公钥文件路径
 */
+ (NSString *)encryptString:(NSString *)str publicKeyWithContentsOfFile:(NSString *)path;

/**
 *  解密方法
 *
 *  @param str       需要解密的字符串
 *  @param path      '.p12'格式的私钥文件路径
 *  @param password  私钥文件密码
 */
+ (NSString *)decryptString:(NSString *)str privateKeyWithContentsOfFile:(NSString *)path password:(NSString *)password;

/**
 *  加密方法
 *
 *  @param str    需要加密的字符串
 *  @param pubKey 公钥字符串
 */
+ (NSString *)encryptString:(NSString *)str publicKey:(NSString *)pubKey;

/**
 *  解密方法
 *
 *  @param str     需要解密的字符串
 *  @param privKey 私钥字符串
 */
+ (NSString *)decryptString:(NSString *)str privateKey:(NSString *)privKey;

/**
 公钥加密

 @param data 元数据
 @param pubKey 公钥
 @return 加密后的数据
 */
+ (NSData *)encryptData:(NSData *)data publicKey:(NSString *)pubKey;

/**
 私钥解密

 @param data 加密后的数据
 @param privKey 秘钥
 @return 元数据
 */
+ (NSData *)decryptData:(NSData *)data privateKey:(NSString *)privKey;

//公钥解密
+ (NSString *)decryptString:(NSString *)str publicKeyWithContentsOfFile:(NSString *)path;

//私钥加密
+ (NSString *)encryptString:(NSString *)str privateKeyWithContentsOfFile:(NSString *)path password:(NSString *)password;

@end
