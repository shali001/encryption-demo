package com.amos.encryption.symmetry;


import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * @ClassName : DESEncryption
 * @Description :des加密解密
 * @Author : mlb
 * @Date: 2020-07-21 15:38
 */
public class AESEncryption {

    /**
     * 密钥算法
     */
    private static final String ALGORITHM = "AES";
    /**
     * 加密/解密算法-工作模式-填充模式
     */
    private static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";


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
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, random);
        byte[] encryptedData = cipher.doFinal(data.getBytes());

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
        cipher.init(Cipher.DECRYPT_MODE, secretKey, random);
        byte[] dataBytes = Base64.decodeBase64(data);
        byte[] decryptedData = cipher.doFinal(dataBytes);
        // 解密后的内容
        return new String(decryptedData, "UTF-8");
    }

    /**
     * 获取秘钥
     *
     * @author meng_lbo
     * @date 2020/7/23  10:22
     */
    private static SecretKeySpec getSecretKey(String key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM);
        // AES 要求密钥长度为128位、192位或256位
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(key.getBytes());
        generator.init(256, random);
        SecretKey secretKey = generator.generateKey();
        return new SecretKeySpec(secretKey.getEncoded(), ALGORITHM);
    }


    public static void main(String[] args) {
        try {
            //String key = getKey("123456");
            //System.out.println("秘钥:" + key);
            String text = "PS:RSA加密对明文的长度有所限制，规定需加密的明文最大长度=密钥长度-11（单位是字节，即byte），所以在加密和解密的过程中需要分块进行。而密钥默认是1024位，即1024位/8位-11=128-11=117字节。所以默认加密前的明文最大长度117字节，解密密文最大长度为128字。那么为啥两者相差11字节呢？是因为RSA加密使用到了填充模式（padding），即内容不足117字节时会自动填满，用到填充模式自然会占用一定的字节，而且这部分字节也是参与加密的。\n" +
                    "\n" +
                    "　　密钥长度的设置就是上面例子的第32行。可自行调整，当然非对称加密随着密钥变长，安全性上升的同时性能也会有所下降。";
            String pwd = encrypt(text, "321");
            System.out.println("秘文:" + pwd);
            String data = decrypt(pwd, "321");
            System.out.println("明文:" + data);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("加解密异常");
        }
    }

}
