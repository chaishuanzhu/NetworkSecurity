package com.example.SpringBootDemo.utils;

import org.apache.tomcat.util.buf.HexUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DES {
    public static final String PASSWORD_CRYPT_KEY = "Fu0uVgOO";
    private static byte[] iv = {1,2,3,4,5,6,7,8};

    public static String encryptDES(String encryptString, String encryptKey)
            throws Exception {
        IvParameterSpec zeroIv = new IvParameterSpec(iv);
        SecretKeySpec key = new SecretKeySpec(encryptKey.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, zeroIv);
        byte[] encryptedData = cipher.doFinal(encryptString.getBytes());
        return HexUtils.toHexString(encryptedData);
    }

    public static String decryptDES(String decryptString, String decryptKey)
            throws Exception {
        byte[] byteMi = HexUtils.fromHexString(decryptString);
        IvParameterSpec zeroIv = new IvParameterSpec(iv);
        SecretKeySpec key = new SecretKeySpec(decryptKey.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, zeroIv);
        byte decryptedData[] = cipher.doFinal(byteMi);
        return new String(decryptedData);
    }

    public static byte[] encrypt(byte[] data, String encryptKey)
            throws Exception {
        IvParameterSpec zeroIv = new IvParameterSpec(iv);
        SecretKeySpec key = new SecretKeySpec(encryptKey.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, zeroIv);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, String decryptKey)
            throws Exception {
        IvParameterSpec zeroIv = new IvParameterSpec(iv);
        SecretKeySpec key = new SecretKeySpec(decryptKey.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, zeroIv);
        return cipher.doFinal(data);
    }

    // DES 秘钥长度
    // kCCKeySizeDES = 8,
    // kCCKeySize3DES = 24,
    public static void main(String[]args) throws Exception{
        String plaintext = "aes encrypt test client send";
        String ciphertext = DES.encryptDES(plaintext, DES.PASSWORD_CRYPT_KEY);
        System.out.println("明文：" + plaintext);
        System.out.println("密钥：" + DES.PASSWORD_CRYPT_KEY);
        System.out.println("密文：" + ciphertext);
        System.out.println("解密后：" + DES.decryptDES(ciphertext, DES.PASSWORD_CRYPT_KEY));
    }
}