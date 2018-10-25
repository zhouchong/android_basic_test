package com.tony.basictest;

import android.util.Base64;

import com.LogUtil.LogUtil;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DES {
    private static final String TAG = "DES";

    //加密
    public byte[] encrypt(byte[] key){
        LogUtil.d(TAG, "3DES Key: " + Utils.byte2HexStr(key));

        //生成密钥
        SecretKey desKey = new SecretKeySpec(key, "DESede");

        try {
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, desKey);

            byte[] data = new byte[16];
            for (int i=0; i<data.length; i++)
                data[0] = 0;
            byte[] ret = cipher.doFinal(data);

            //LogUtil.d(TAG, "3DES: " + Base64.encodeToString(ret, Base64.DEFAULT));
            LogUtil.d(TAG, "3DES  Out: " + Utils.byte2HexStr(ret));

            return ret;
        } catch (Exception ex) {
            //加密失败，打日志
            //加密失败，打日志
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * 对8bytes 0 进行加密
     * @param key 16 bytes key
     * @param data 要加密的数据, 长度是8的倍数
     * @return 加密后的数据
     */
    public static byte[] encrypt3DES(byte[] key, byte[] data) {
        byte[] key24 = new byte[24];
        byte[] iv = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

        if (key == null) {
            LogUtil.e(TAG, "encrypt3DES key is null!");
            return null;
        }

        //LogUtil.d(TAG, "encrypt3DES Key: " + Utils.byte2HexStr(key));

        if (key.length != 16) {
            LogUtil.e(TAG, "encrypt3DES length of key is not 16 bytes!!");
            return null;
        }

        System.arraycopy(key, 0, key24, 0, 16);
        System.arraycopy(key, 0, key24, 16, 8);

        //生成密钥
        SecretKey desKey = new SecretKeySpec(key24, "DESede");

        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, desKey, new IvParameterSpec(iv));
            byte[] ret = cipher.doFinal(data);

            //LogUtil.d(TAG, "encrypt3DES Out: " + Utils.byte2HexStr(ret));
            return ret;
        } catch (Exception ex) {
            LogUtil.e(TAG, "3DES加密失败");
            ex.printStackTrace();
        }
        return null;
    }

    public byte[] decrypt(byte[] key, byte[] data){
        //生成密钥
        SecretKey desKey = new SecretKeySpec(key, "DESede");

        try {
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, desKey);
            return cipher.doFinal(data);
        } catch (Exception ex) {
            //解密失败，打日志
            ex.printStackTrace();
        }
        return null;
    }

}
