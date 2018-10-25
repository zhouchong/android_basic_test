package com.tony.basictest;

public class TLEMAC {
    public static byte[] calcMAC(byte[] key, byte[] data) throws Exception {
        String sha1Hex = has1.sha1(new String(data, "ISO-8859-1"));

        byte[] encryptData = new byte[24];
        System.arraycopy(Utils.asc2Bcd(sha1Hex), 0, encryptData, 0, 20);
        encryptData[20] = (byte)0x80;

        byte desData[] = DES.encrypt3DES(key, encryptData);
        byte MAB[] = new byte[8];
        System.arraycopy(desData, desData.length - 8, MAB, 0, 8);
        byte MAC[] = new byte[4];
        System.arraycopy(MAB, 0, MAC, 0, 4);

        return MAC;
    }
}
