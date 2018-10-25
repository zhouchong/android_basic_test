package com.tony.basictest;


import android.util.Base64;
import com.LogUtil.LogUtil;
import javax.crypto.Cipher;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


/**
 * 非对称加密算法RSA算法组件
 * 非对称算法一般是用来传送对称加密算法的密钥来使用的，相对于DH算法，RSA算法只需要一方构造密钥，不需要
 * 大费周章的构造各自本地的密钥对了。DH算法只能算法非对称算法的底层实现。而RSA算法算法实现起来较为简单
 *
 * @author kongqz
 */
public class RSA {
    private static final String TAG = "RSA";
    //非对称密钥算法
    public static final String KEY_ALGORITHM = "RSA";

    /** 指定公钥存放文件 */
    private static String PUBLIC_KEY_FILE = "PublicKey";
    /** 指定私钥存放文件 */
    private static String PRIVATE_KEY_FILE = "PrivateKey";


    /**
     * 密钥长度，DH算法的默认密钥长度是1024
     * 密钥长度必须是64的倍数，在512到65536位之间
     */
    private static final int KEY_SIZE = 2048;

    /**
     * 私钥加密
     *
     * @param data 待加密数据
     * @param key  密钥
     * @return byte[] 加密数据
     */
    public static byte[] encryptByPrivateKey(byte[] data, byte[] key) throws Exception {

        //取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        //生成私钥
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        //数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 公钥加密
     *
     * @param data 待加密数据
     * @param key  密钥
     * @return byte[] 加密数据
     */
    public static byte[] encryptByPublicKey(byte[] data, byte[] key) throws Exception {

        //实例化密钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        //初始化公钥
        //密钥材料转换
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);
        //产生公钥
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

        //数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(data);
    }

    /**
     * 私钥解密
     *
     * @param data 待解密数据
     * @param key  密钥
     * @return byte[] 解密数据
     */
    public static byte[] decryptByPrivateKey(byte[] data, byte[] key) throws Exception {
        //取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);
        //X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        //生成私钥
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        //数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 公钥解密
     *
     * @param data 待解密数据
     * @param key  密钥
     * @return byte[] 解密数据
     */
    public static byte[] decryptByPublicKey(byte[] data, byte[] key) throws Exception {

        //实例化密钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        //初始化公钥
        //密钥材料转换
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);
        //产生公钥
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
        //数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        return cipher.doFinal(data);
    }

    //公钥加密
    public static byte[] encrypt(byte[] content, PublicKey publicKey) throws Exception{
        Cipher cipher=Cipher.getInstance("RSA");//java默认"RSA"="RSA/ECB/PKCS1Padding"
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }

    //私钥解密
    public static byte[] decrypt(byte[] content, PrivateKey privateKey) throws Exception{
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(content);
    }


    /**
     * @throws Exception
     */
    public static void main() throws Exception {
/*        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        //初始化密钥生成器
        keyPairGenerator.initialize(KEY_SIZE);
        //生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //甲方公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        BigInteger publicExponent = publicKey.getPublicExponent();
        BigInteger publicModulus = publicKey.getModulus();
        //甲方私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        LogUtil.d(TAG,"=====================================================================");
        LogUtil.d(TAG,"公钥长度: " + publicKey.getEncoded().length);
        LogUtil.d(TAG, "公钥:\n" + Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT));

        LogUtil.d(TAG,"=====================================================================");
        LogUtil.d(TAG,"私钥长度: " + privateKey.getEncoded().length);
        LogUtil.d(TAG, "私钥:\n" + Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT));

        LogUtil.d(TAG,"=====================================================================");
        LogUtil.d(TAG, "公钥指数: " + publicExponent.toString(16));

        LogUtil.d(TAG,"=====================================================================");
        LogUtil.d(TAG, "公钥modulus长度: " + publicModulus.toString(16).length());
        LogUtil.d(TAG, "公钥modulus:\n" + publicModulus.toString(16));
        LogUtil.d(TAG,"=====================================================================");*/

        byte[] key = "1111111111111111".getBytes();
        byte[] encryptData = new DES().encrypt(key);
        byte[] decryptData = new DES().decrypt(key, encryptData);
        LogUtil.d(TAG,"解密数据长度: " + decryptData.length);
        LogUtil.d(TAG,"解密数据: " + Utils.byte2HexStr(decryptData));

/*        ObjectOutputStream oos1 = null;
        ObjectOutputStream oos2 = null;
        try {
            *//** 用对象流将生成的密钥写入文件 *//*
            oos1 = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE));
            oos2 = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE));
            oos1.writeObject(publicKey);
            oos2.writeObject(privateKey);
        } catch (Exception e) {
            throw e;
        } finally {
            *//** 清空缓存，关闭文件输出流 *//*
            oos1.close();
            oos2.close();
        }*/


//        System.out.println("================密钥对构造完毕,甲方将公钥公布给乙方，开始进行加密数据的传输=============");
//        String str = "RSA密码交换算法";
//        System.out.println("/n===========甲方向乙方发送加密数据==============");
//        System.out.println("原文:" + str);
//        //甲方进行数据的加密
//        byte[] code1 = encryptByPrivateKey(str.getBytes(), privateKey);
//        System.out.println("加密后的数据：" + Base64.encodeToString(code1, Base64.DEFAULT));
//        System.out.println("===========乙方使用甲方提供的公钥对数据进行解密==============");
//        //乙方进行数据的解密
//        byte[] decode1 = decryptByPublicKey(code1, publicKey);
//        System.out.println("乙方解密后的数据：" + new String(decode1) + "/n/n");
//
//        System.out.println("===========反向进行操作，乙方向甲方发送数据==============/n/n");
//
//        str = "乙方向甲方发送数据RSA算法";
//
//        System.out.println("原文:" + str);

        String str = "1234567890123456";

/*        //乙方使用公钥对数据进行加密
        byte[] code2 = encryptByPublicKey(str.getBytes(), publicKey.getEncoded());
        System.out.println("===========乙方使用公钥对数据进行加密==============");
        System.out.println("加密后的数据长度：" + code2.length);
        System.out.println("加密后的数据：" + Base64.encodeToString(code2, Base64.DEFAULT));

        System.out.println("=============乙方将数据传送给甲方======================");
        System.out.println("===========甲方使用私钥对数据进行解密==============");

        //甲方使用私钥对数据进行解密
        byte[] decode2 = decryptByPrivateKey(code2, privateKey.getEncoded());

        System.out.println("甲方解密后的数据：" + new String(decode2));*/
    }
}

