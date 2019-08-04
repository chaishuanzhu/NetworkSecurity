package com.example.SpringBootDemo.utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @Author: Roylion
 * @Description: AES算法封装
 * @Date: Created in 9:46 2018/8/9
 */
public class AES {

    /**
     * 加密算法
     */
    private static final String ENCRY_ALGORITHM = "AES";

    /**
     * 加密算法/加密模式/填充类型
     * 本例采用AES加密，ECB加密模式，PKCS5Padding填充
     */
    private static final String CIPHER_MODE = "AES/ECB/PKCS5Padding";

    /**
     * 原始加密
     * @param clearTextBytes 明文字节数组，待加密的字节数组
     * @param key 加密秘钥
     * @return 返回加密后的密文字节数组，加密错误返回null
     */
    public static byte[] encrypt(byte[] clearTextBytes, String key) throws Exception {
        // 1 获取加密密钥
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), ENCRY_ALGORITHM);

        // 2 获取Cipher实例
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);

        // 查看数据块位数 默认为16（byte） * 8 =128 bit
//            System.out.println("数据块位数(byte)：" + cipher.getBlockSize());

        // 3 初始化Cipher实例。设置执行模式以及加密密钥
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        // 4 执行
        byte[] cipherTextBytes = cipher.doFinal(clearTextBytes);

        // 5 返回密文字符集
        return cipherTextBytes;
    }

    /**
     * 原始解密
     * @param cipherTextBytes 密文字节数组，待解密的字节数组
     * @param key 解密秘钥
     * @return 返回解密后的明文字节数组，解密错误返回null
     */
    public static byte[] decrypt(byte[] cipherTextBytes, String key) throws Exception {
        // 1 获取解密密钥
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), ENCRY_ALGORITHM);

        // 2 获取Cipher实例
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);

        // 查看数据块位数 默认为16（byte） * 8 =128 bit
//            System.out.println("数据块位数(byte)：" + cipher.getBlockSize());

        // 3 初始化Cipher实例。设置执行模式以及加密密钥
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        // 4 执行
        byte[] clearTextBytes = cipher.doFinal(cipherTextBytes);

        // 5 返回明文字符集
        return clearTextBytes;
    }


    // AES 秘钥长度
    // kCCKeySizeAES128 = 16,
    // kCCKeySizeAES192 = 24,(JCE)
    // kCCKeySizeAES256 = 32,(JCE)
    public static void main(String[] args) throws Exception {
        byte[] test = encrypt("test".getBytes(), "1234567800000000");
        System.out.println(test);
        System.out.println(decrypt(test, "1234567800000000"));
    }
}