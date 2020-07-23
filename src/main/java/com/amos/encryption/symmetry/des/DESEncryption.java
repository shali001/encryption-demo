package com.amos.encryption.symmetry.des;


import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * @ClassName : DESEncryption
 * @Description :des加密解密
 * @Author : mlb
 * @Date: 2020-07-21 15:38
 */
public class DESEncryption {

    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;


    /**
     * 加密
     *
     * @param data 原始数据
     * @param key  秘钥
     * @return 密文
     * @author meng_lbo
     * @date 2020/7/23  10:19
     */
    public static String encrypt(String data, String key) throws Exception {
        //获取秘钥
        SecretKey secretKey = getSecretKey(key);
        //加密
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = getBytes(cipher, data.getBytes(), MAX_ENCRYPT_BLOCK);

        return Base64.encodeBase64String(encryptedData);
    }


    /**
     * 解密
     *
     * @param data 密文
     * @param key  秘钥
     * @return 明文
     * @author meng_lbo
     * @date 2020/7/23  10:19
     */
    public static String decrypt(String data, String key) throws Exception {
        //获取秘钥
        SecretKey secretKey = getSecretKey(key);
        //设置解密方式
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //解密
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] dataBytes = Base64.decodeBase64(data);
        byte[] decryptedData = getBytes(cipher, dataBytes, MAX_DECRYPT_BLOCK);
        // 解密后的内容
        return new String(decryptedData, "UTF-8");
    }

    /**
     * 分段处理数据
     *
     * @author meng_lbo
     * @date 2020/7/23  10:19
     */
    private static byte[] getBytes(Cipher cipher, byte[] dataBytes, int maxDecryptBlock) throws IllegalBlockSizeException, BadPaddingException, IOException {
        int inputLen = dataBytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offset > 0) {
            if (inputLen - offset > maxDecryptBlock) {
                cache = cipher.doFinal(dataBytes, offset, maxDecryptBlock);
            } else {
                cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * maxDecryptBlock;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /**
     * 获取秘钥
     *
     * @author meng_lbo
     * @date 2020/7/23  10:22
     */
    private static SecretKey getSecretKey(String key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] b = Base64.decodeBase64(key.getBytes());
        DESKeySpec dks = new DESKeySpec(b);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        return keyFactory.generateSecret(dks);
    }

    /**
     * 获取密钥对
     *
     * @return 密钥对
     */
    private static String getKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("DES");
        generator.init(56);
        SecretKey key = generator.generateKey();
        return Base64.encodeBase64String(key.getEncoded());
        // SecretKey byte[]相互转换
       /* byte[] b = key.getEncoded();
       //对于DESede算法，则需要相应的DESedeKeySpec类替换DESKeySpec类来完成操作。
        DESKeySpec dks = new DESKeySpec(b);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(dks);*/
    }

    public static void main(String[] args) {
        try {
            String key = getKey();
            System.out.println("秘钥:" + key);
            String text = "我是原始数据";
            String pwd = encrypt(text, key);
            System.out.println("秘文:" + pwd);
            String data = decrypt(pwd, key);
            System.out.println("明文:" + data);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("加解密异常");
        }
    }

}
