package com.amos.encryption.symmetry;


import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * @ClassName : DESedeEncryption
 * @Description :DESede加密解密,秘钥长度更长，优于DES
 * @Author : mlb
 * @Date: 2020-07-21 15:38
 */
public class DESedeEncryption {

    /**
     * 密钥算法
     */
    private static final String ALGORITHM = "DESede";
    /**
     * 加密/解密算法-工作模式-填充模式
     */
    private static final String CIPHER_ALGORITHM = "DESede/ECB/PKCS5Padding";


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
        SecureRandom random = new SecureRandom();
        //获取秘钥
        SecretKey secretKey = getSecretKey(key);
        //加密
        //
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey,random);
        byte[] encryptedData =  cipher.doFinal(data.getBytes());

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
        SecureRandom random = new SecureRandom();
        //获取秘钥
        SecretKey secretKey = getSecretKey(key);
        //设置解密方式
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        //解密
        cipher.init(Cipher.DECRYPT_MODE, secretKey,random);
        byte[] dataBytes = Base64.decodeBase64(data);
        byte[] decryptedData = cipher.doFinal(dataBytes);
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
        byte[] decryptedData = cipher.doFinal(dataBytes);
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
        DESedeKeySpec dks = new DESedeKeySpec (b);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        return keyFactory.generateSecret(dks);
    }

    /**
     * 获取密钥对
     *
     * @return 密钥对
     */
    private static String getKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM);
        // 密钥长度为112位、168位
        generator.init(168);
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
            String text = "PS:RSA加密对明文的长度有所限制，规定需加密的明文最大长度=密钥长度-11（单位是字节，即byte），所以在加密和解密的过程中需要分块进行。而密钥默认是1024位，即1024位/8位-11=128-11=117字节。所以默认加密前的明文最大长度117字节，解密密文最大长度为128字。那么为啥两者相差11字节呢？是因为RSA加密使用到了填充模式（padding），即内容不足117字节时会自动填满，用到填充模式自然会占用一定的字节，而且这部分字节也是参与加密的。\n" +
                    "\n" +
                    "　　密钥长度的设置就是上面例子的第32行。可自行调整，当然非对称加密随着密钥变长，安全性上升的同时性能也会有所下降。";
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
