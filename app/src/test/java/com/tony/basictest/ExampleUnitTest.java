package com.tony.basictest;

import com.LogUtil.LogUtil;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.*;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    private static final String TAG = "ExampleUnitTest";

    @Test
    public void addition_isCorrect() throws Exception {
        assertEquals(4, 2 + 2);
    }

    @Test
    public void calcTxnHash() throws Exception {
        String TE_ID = "00000001";
        String TE_PIN = "99999999";
        String PIN_END_STR = "1234";

        String TerminalID = "12345678";
        String TranceNo = "123456";

        String hash_data = calcTLEHash(TE_ID, TE_PIN, "9991234");

        String txn_hash = calcTLEHash(hash_data, TerminalID, TranceNo);

        System.out.println("---------txn_hash: " + txn_hash);
    }

    private String calcTLEHash(String string1, String string2, String string3) throws Exception {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(string1);
        stringBuilder.append(string2);
        stringBuilder.append(string3.substring(string3.length() - 4));
        String PIN_hash = sha1(stringBuilder.toString());
        return PIN_hash.substring(0, 8).toUpperCase();
    }

    private static String sha1(String data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        try {
            md.update(data.getBytes("ISO-8859-1"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        StringBuilder buf = new StringBuilder();
        byte[] bits = md.digest();
        for (int i = 0; i < bits.length; i++) {
            int a = bits[i];
            if (a < 0) a += 256;
            if (a < 16) buf.append("0");
            buf.append(Integer.toHexString(a));
        }
        return buf.toString();
    }

    @Test
    public void arrayTest() throws Exception {
        byte[] key = "1234567890123456".getBytes(); //16
        byte[] encryptData = encrypt3DES(key);
        byte[] decryptData = decrypt3DES(key, encryptData);
        LogUtil.d(TAG,"解密数据长度: " + decryptData.length);
        LogUtil.d(TAG,"解密数据: " + Utils.byte2HexStr(decryptData));
    }

    private byte[] encrypt3DES(byte[] key) {
        byte[] key24 = new byte[24];
        byte[] iv = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

        System.arraycopy(key, 0, key24, 0, 16);
        System.arraycopy(key, 0, key24, 16, 8);
        LogUtil.d(TAG, "3DES Key: " + Utils.byte2HexStr(key));
        //生成密钥
        SecretKey desKey = new SecretKeySpec(key24, "DESede");

        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, desKey, new IvParameterSpec(iv));

            byte[] ret = cipher.doFinal(new byte[8]);

            LogUtil.d(TAG, "3DES Out: " + Utils.byte2HexStr(ret));

            return ret;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private byte[] encrypt3DES(byte[] key, byte[] data) {
        byte[] key24 = new byte[24];
        byte[] iv = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

        System.arraycopy(key, 0, key24, 0, 16);
        System.arraycopy(key, 0, key24, 16, 8);
        LogUtil.d(TAG, "3DES Key: " + Utils.byte2HexStr(key));
        //生成密钥
        SecretKey desKey = new SecretKeySpec(key24, "DESede");

        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, desKey, new IvParameterSpec(iv));

            byte[] ret = cipher.doFinal(data);

            LogUtil.d(TAG, "3DES Out: " + Utils.byte2HexStr(ret));

            return ret;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public byte[] decrypt3DES(byte[] key, byte[] data){
        byte[] key24 = new byte[24];
        byte[] iv = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

        System.arraycopy(key, 0, key24, 0, 16);
        System.arraycopy(key, 0, key24, 16, 8);
        //生成密钥
        SecretKey desKey = new SecretKeySpec(key24, "DESede");

        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, desKey, new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (Exception ex) {
            //解密失败，打日志
            ex.printStackTrace();
        }
        return null;
    }

    @Test
    public void mTest() throws Exception {
        String data = "02002020058000C00481002000044932002201010037373938303032353830303235202020202020202020200012303030303030303030303031022048544C453033303031383030303030303132303130303034303030383137370000000000E1FF4BFC6115C38F157D3E13BF03D3B2033875D939BE605B83123C738660F9A9C3E1BEEFA6BC64D11957077CCF3B6EE8CBD22AA2E0AFB5373359983FEBB32245CF5E5BF8EF7EDC036CD534AD11FFDB6962F80A11F3AB29CF63F381463D58A69B618D3680384753C62BB6B75B3FE5E8FCC334716CF24ADC7BEB70A864C2D93B5A27EB02AC87ABE7909A569BA493954883DAE6FE4FFED46B2067775BF18962070EDCA57BF68C928F80D986A43F7B4BCBF8E124A8D8543D73C3";
        //except: E4 10 0F 1F
        String hasData128 = "243B90B4B81D06418BB40E06E99B0F1A3A02BC7C8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        String hasData64 = "243B90B4B81D06418BB40E06E99B0F1A3A02BC7C800000000000000000000000";
        String hasData48 = "243B90B4B81D06418BB40E06E99B0F1A3A02BC7C80000000";

        String data1 = "0210203801000E80020100200004493214535111210101383332353036353335313030393030363632303037373938303032350026010017910A1234567890BCDEF0303071031A2B3C9F1E03F1F2F3";
        String has1Data64 = "ED972D3FBF8F36BBC6C50EE3C4A47174119BFE5680000000";

        String sha1Hex = sha1(Utils.hexStr2Str(data1));

        String hasData = hasData128;

        System.out.println(sha1Hex);

        try {
            byte[] tdesOut = encrypt3DES("1111111111111111".getBytes(), Utils.hexStr2Str(has1Data64).getBytes("ISO-8859-1"));
            System.out.println(Utils.byte2HexStr(tdesOut));
        } catch (Exception e) {
            e.printStackTrace();
        }
//        byte[] hello = Utils.asc2Bcd("243B90B4B81D06418BB40E06E99B0F1A3A02BC7C800000000000000000000000");
//        System.out.println("byte length: " + hello.length + "\n");
//        LogUtil.d(TAG,"hello: " + Utils.byte2HexStr(hello));
        //System.out.println("encodeHmacSHA");
        //System.out.println(encodeHmacSHA(Utils.asc2Bcd(hasData), "1111111111111111".getBytes()));

        //System.out.println(Utils.byte2HexStr(cbcEncrypt(Utils.asc2Bcd(hasData), "1111111111111111".getBytes(), new byte[8])));

        byte[] mac = TLEMAC.calcMAC("1111111111111111".getBytes(), Utils.asc2Bcd(data1));
        LogUtil.d(TAG,"my clac mac: " + Utils.byte2HexStr(mac));
    }

    /**
     * 加密函数(CBC)
     *
     * @param data
     *            加密数据
     * @param key
     *            密钥
     * @return 返回加密后的数据
     */
    private static byte[] cbcEncrypt(byte[] data, byte[] key, byte[] iv) {

        try {
            // 从原始密钥数据创建DESKeySpec对象
            DESKeySpec dks = new DESKeySpec(key);

            // 创建一个密匙工厂，然后用它把DESKeySpec转换成一个SecretKey对象
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(dks);

            // DES的CBC模式,采用NoPadding模式，data长度必须是8的倍数
            Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");

            // 用密钥初始化Cipher对象
            IvParameterSpec param = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, param);

            // 执行加密操作
            byte encryptedData[] = cipher.doFinal(data);

            return encryptedData;
        } catch (Exception e) {
            throw new RuntimeException("CBC-DES算法，加密数据出错!");
        }
    }


        /**
         * HmacSHA1摘要算法
         * 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
         */
    public static String encodeHmacSHA(byte[] data, byte[] key) throws Exception {
        // 还原密钥
        SecretKey secretKey = new SecretKeySpec(key, "HmacSHA1");
        //SecretKey secretKey = new SecretKeySpec(key, "DESedeMAC");
        // 实例化Mac
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        //初始化mac
        mac.init(secretKey);
        //执行消息摘要
        byte[] digest = mac.doFinal(data);
        return Utils.byte2HexStr(digest);//转为十六进制的字符串
    }

    @Test
    public void macTest() throws Exception {
        String mac = MAC.analogMacBy3Des("1111111111111111", new String(Utils.asc2Bcd("243B90B4B81D06418BB40E06E99B0F1A3A02BC7C800000000000000000000000"), "ISO-8859-1"));
        LogUtil.d(TAG,"MAC: " + mac);
    }
}