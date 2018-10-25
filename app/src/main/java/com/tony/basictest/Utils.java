package com.tony.basictest;

import com.LogUtil.LogUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;


/**
 * Created by laikey on 2016/12/11.
 */

public class Utils {

    private static String TAG = "Utils";

    public Utils() {
    }

    public static String bcd2Asc(byte[] bcd) {
        if (bcd == null || bcd.length <= 0) {
            return null;
        } else {
            try {
                String stmp = "";
                StringBuilder sb = new StringBuilder("");

                for (int i = 0; i < bcd.length; ++i) {
                    stmp = Integer.toHexString(bcd[i] & 255);
                    sb.append(stmp.length() == 1 ? "0" + stmp : stmp);
                }

                return sb.toString().toUpperCase().trim();
            } catch (Exception e) {
            }
            return null;
        }
    }

    public static String bcd2Asc(byte[] bcd, int length) {
        if (bcd == null || bcd.length <= 0 || length <= 0 || length > bcd.length) {
            return null;
        }
        try {
            String stmp = "";
            StringBuilder sb = new StringBuilder("");
            for (int i = 0; i < length; i++) {
                stmp = Integer.toHexString(bcd[i] & 0xFF);
                sb.append(stmp.length() == 1 ? "0" + stmp : stmp);
            }
            return sb.toString().toUpperCase().trim();
        } catch (Exception e) {
        }
        return null;
    }

    public static String bcd2Str(byte[] bcd) {
        if (bcd == null || bcd.length <= 0) return null;
        char[] ascii = "0123456789abcdef".toCharArray();
        byte[] temp = new byte[bcd.length * 2];

        try {
            for (int i = 0; i < bcd.length; i++) {
                temp[(i * 2)] = ((byte) (bcd[i] >> 4 & 0xF));
                temp[(i * 2 + 1)] = ((byte) (bcd[i] & 0xF));
            }
            StringBuffer res = new StringBuffer();
            for (int i = 0; i < temp.length; i++) {
                res.append(ascii[temp[i]]);
            }
            return res.toString().toUpperCase();
        } catch (Exception e) {
        }
        return null;
    }

    public static String bcd2Str(byte[] bcd, int ascLen) {
        if (bcd == null || bcd.length <= 0) return null;
        char[] ascii = "0123456789abcdef".toCharArray();
        byte[] temp = new byte[bcd.length * 2];

        try {
            for (int i = 0; i < bcd.length; i++) {
                if (i * 2 < ascLen) {
                    temp[(i * 2)] = ((byte) (bcd[i] >> 4 & 0xF));
                }
                if (i * 2 + 1 < ascLen) {
                    temp[(i * 2 + 1)] = ((byte) (bcd[i] & 0xF));
                }
            }
            StringBuffer res = new StringBuffer();
            for (int i = 0; i < ascLen; i++) {
                res.append(ascii[temp[i]]);
            }
            return res.toString().toUpperCase();
        } catch (Exception e) {
        }
        return null;
    }

    public static byte[] asc2Bcd(String asc) {
        if (asc == null) {
            return null;
        }
        return asc2Bcd(asc, asc.length());
    }

    public static byte[] asc2Bcd(String asc, int length) {
        if (asc == null || asc.length() <= 0 || length <= 0 || length > asc.length()) {
            return null;
        }

        try {
            int len = length;
            int mod = len % 2;
            if (mod != 0) {

                asc = "0" + asc;
                len += 1;
            }
            byte[] abt = new byte[len];
            if (len >= 2) {
                len /= 2;
            }
            byte[] bbt = new byte[len];
            abt = asc.getBytes();
            for (int p = 0; p < len; p++) {
                int j;
                if ((abt[(2 * p)] >= 48) && (abt[(2 * p)] <= 57)) {
                    j = abt[(2 * p)] - 48;
                } else {
                    if ((abt[(2 * p)] >= 97) && (abt[(2 * p)] <= 122)) {
                        j = abt[(2 * p)] - 97 + 10;
                    } else {
                        j = abt[(2 * p)] - 65 + 10;
                    }
                }
                int k;
                if ((abt[(2 * p + 1)] >= 48) && (abt[(2 * p + 1)] <= 57)) {
                    k = abt[(2 * p + 1)] - 48;
                } else {
                    if ((abt[(2 * p + 1)] >= 97) && (abt[(2 * p + 1)] <= 122)) {
                        k = abt[(2 * p + 1)] - 97 + 10;
                    } else {
                        k = abt[(2 * p + 1)] - 65 + 10;
                    }
                }
                int a = (j << 4) + k;
                byte b = (byte) a;
                bbt[p] = b;
            }
            return bbt;
        } catch (Exception e) {
        }
        return null;
    }

    // fx 增加Utils.asc2BcdLeft()方法，用于ASC字符数量为奇数时数据左对齐。(asc2Bcd()是右对齐的)
    public static byte[] asc2BcdLeft(String asc, int length) {
        if (asc == null || asc.length() <= 0 || length <= 0 || length > asc.length()) {
            return null;
        }

        try {
            int len = length;
            int mod = len % 2;
            if (mod != 0) {
                // fx   变长域，右补0
                // asc = "0" + asc;
                asc = asc + "0";
                len += 1;
            }
            byte[] abt = new byte[len];
            if (len >= 2) {
                len /= 2;
            }
            byte[] bbt = new byte[len];
            abt = asc.getBytes();
            for (int p = 0; p < len; p++) {
                int j;
                if (((abt[(2 * p)] >= 48) && (abt[(2 * p)] <= 57)) || (abt[(2 * p)] == 61)) {
                    j = abt[(2 * p)] - 48;
                } else {
                    if ((abt[(2 * p)] >= 97) && (abt[(2 * p)] <= 122)) {
                        j = abt[(2 * p)] - 97 + 10;
                    } else {
                        j = abt[(2 * p)] - 65 + 10;
                    }
                }


                int k;
                if (((abt[(2 * p + 1)] >= 48) && (abt[(2 * p + 1)] <= 57)) || (abt[(2 * p + 1)] == 61)) {
                    k = abt[(2 * p + 1)] - 48;
                } else {
                    if ((abt[(2 * p + 1)] >= 97) && (abt[(2 * p + 1)] <= 122)) {
                        k = abt[(2 * p + 1)] - 97 + 10;
                    } else {
                        k = abt[(2 * p + 1)] - 65 + 10;
                    }
                }
                int a = (j << 4) + k;
                byte b = (byte) a;
                bbt[p] = b;
            }
            return bbt;
        } catch (Exception e) {
        }
        return null;
    }

    public static String byte2HexStr(byte[] data) {
        if (data == null || data.length <= 0) {
            return null;
        }
        try {
            String stmp = "";
            StringBuilder sb = new StringBuilder("");
            for (int n = 0; n < data.length; n++) {
                stmp = Integer.toHexString(data[n] & 0xFF);
                sb.append(stmp.length() == 1 ? "0" + stmp : stmp);
            }
            return sb.toString().toUpperCase().trim();
        } catch (Exception e) {
        }
        return null;
    }

    public static String byte2HexStr(byte[] data, int len) {
        if (data == null || data.length <= 0 || len <= 0 || len > data.length) {
            return null;
        }
        try {
            String stmp = "";
            StringBuilder sb = new StringBuilder("");
            for (int n = 0; n < len; n++) {
                stmp = Integer.toHexString(data[n] & 0xFF);
                sb.append(stmp.length() == 1 ? "0" + stmp : stmp);
            }
            return sb.toString().toUpperCase().trim();
        } catch (Exception e) {
        }
        return null;
    }

    private String byte2HexStr(byte[] data, int offset, int len) {
        if (data == null || data.length <= 0 || offset < 0 || len <= 0 || offset > data.length || len > data.length - offset) {
            return null;
        }
        try {
            byte[] d = Utils.subBytes(data, offset, len);
            String str = Utils.byte2HexStr(d);
            return str;
        } catch (Exception e) {
        }
        return null;
    }

    public static String byte2Str(byte[] byteData) {
        if (byteData == null || byteData.length <= 0) {
            return null;
        }
        try {
            StringBuilder buf = new StringBuilder();
            for (int i = 0; i < byteData.length; i++) {
                String tempStr = Integer.toHexString(byteData[i] & 0xff);
                if (tempStr.length() == 1) {
                    buf.append("0").append(tempStr);
                } else {
                    buf.append(tempStr);
                }
            }
            return buf.toString().toLowerCase();
        } catch (Exception e) {
        }
        return null;
    }


    public static byte[] hexStr2Bytes(String src) {
        if (src == null || src.length() <= 0) {
            return null;
        }
        try {
            int m = 0;
            int n = 0;
            if (src.length() % 2 != 0) {
                src = "0" + src;
            }
            int l = src.length() / 2;

            byte[] ret = new byte[l];
            for (int i = 0; i < l; i++) {
                m = i * 2 + 1;
                n = m + 1;
                ret[i] = Integer.decode("0x" + src.substring(i * 2, m) + src.substring(m, n)).byteValue();
            }
            return ret;
        } catch (Exception e) {
        }
        return null;
    }

    public static String hexStr2Str(String hexStr) {
        if (hexStr == null || hexStr.length() <= 0) {
            return null;
        }
        String str = "0123456789ABCDEF";
        char[] hexs = hexStr.toCharArray();
        byte[] bytes = new byte[hexStr.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int n = str.indexOf(hexs[(2 * i)]) * 16;
            n += str.indexOf(hexs[(2 * i + 1)]);
            bytes[i] = ((byte) (n & 0xFF));
        }
        try {
            return new String(bytes, "ISO-8859-1");
        } catch (UnsupportedEncodingException localUnsupportedEncodingException) {
        }
        return "";
    }

    public static String str2Asc(String str) throws UnsupportedEncodingException {
        if (str == null || str.length() <= 0) return null;

        String ascStr = "";
        for (int i = 0; i < str.length(); i++) {
            ascStr += String.format("%02X", str.substring(i, i + 1).getBytes("ISO-8859-1")[0]);
        }
        return ascStr;
    }

    public static String asc2str(String asc, int length) {
        if (asc == null || asc.length() <= 0 || length <= 0 || length > asc.length()) {
            return null;
        }

        try {
            int len = length;
            int mod = len % 2;
//            if (mod != 0) {
//                asc = "0" + asc;
//                len += 1;
//            }
            byte[] abt = new byte[len];
            if (len >= 2) {
                len /= 2;
            }
            String bbt = "";
            abt = asc.getBytes();
            for (int p = 0; p <= len; p++) {
                int j;
                if ((abt[(2 * p)] >= 48) && (abt[(2 * p)] <= 57)) {
                    j = abt[(2 * p)] - 48;
                } else {
                    if ((abt[(2 * p)] >= 97) && (abt[(2 * p)] <= 122)) {
                        j = abt[(2 * p)] - 97 + 10;
                    } else {
                        j = abt[(2 * p)] - 65 + 10;
                    }
                }
                int k;
                if ((abt[(2 * p + 1)] >= 48) && (abt[(2 * p + 1)] <= 57)) {
                    k = abt[(2 * p + 1)] - 48;
                } else {
                    if ((abt[(2 * p + 1)] >= 97) && (abt[(2 * p + 1)] <= 122)) {
                        k = abt[(2 * p + 1)] - 97 + 10;
                    } else {
                        k = abt[(2 * p + 1)] - 65 + 10;
                    }
                }
                int a = (j << 4) + k;
                bbt += String.format("%02X", a);
            }
            return bbt;
        } catch (Exception e) {
        }
        return null;
    }

    public static int bcd2Int(byte[] bcd) {
        if (bcd == null || bcd.length <= 0) {
            return 0;
        }
        try {
            String asc = bcd2Asc(bcd);
            return Integer.parseInt(asc);
        } catch (Exception e) {
        }
        return 0;
    }

    public static byte[] int2Bcd(int intValue) {
        if (intValue < 0) {
            return null;
        }
        String str = String.format("%d", intValue);
        if (str.length() % 2 != 0) {
            str = "0" + str;
        }
        byte[] ret = asc2Bcd(str);
        return ret;
    }

    public static byte[] int2Bcd(int intValue, int bcdLen) {
        if (intValue < 0 || bcdLen <= 0) {
            return null;
        }
        try {
            byte[] ret = new byte[bcdLen];
            Arrays.fill(ret, (byte) 0);

            byte[] b = int2Bcd(intValue);
            if (b.length < bcdLen) {
                System.arraycopy(b, 0, ret, bcdLen - b.length, b.length);
            } else {
                ret = Utils.subBytes(b, 0, bcdLen);
            }
            return ret;
        } catch (Exception e) {
        }
        return null;
    }

    public static long hex2Long(byte[] hexValue) {
        if (hexValue == null || hexValue.length > 4) return 0;

        byte[] hex = new byte[4];
        if (hexValue.length < 4) {
            Arrays.fill(hex, (byte) 0);
            System.arraycopy(hexValue, 0, hex, 4 - hexValue.length, hexValue.length);
        } else {
            System.arraycopy(hexValue, 0, hex, 0, 4);
        }

        long result = 0;
        for (int i = 0; i < hex.length; i++) {
            int tmpVal = hex[i] << 8 * (3 - i);
            switch (i) {
                case 0:
                    tmpVal &= 0xFF000000;
                    break;
                case 1:
                    tmpVal &= 0xFF0000;
                    break;
                case 2:
                    tmpVal &= 0xFF00;
                    break;
                case 3:
                    tmpVal &= 0xFF;
                    break;
            }
            result += tmpVal;
        }
        return result;
    }

    public static byte[] long2Hex(long longValue) {
        byte[] result = new byte[4];
        long l = longValue;

        result[0] = (byte) (l / (256 * 256 * 256));
        l = l % (256 * 256 * 256);
        result[1] = (byte) (l / (256 * 256));
        l = l % (256 * 256);
        result[2] = (byte) (l / 256);
        l = l % 256;
        result[3] = (byte) l;
        return result;
    }

    public static String long2String(long value, int maxStringLength) {
        String str;
        String formatSpace = "";

        for (int i = 0; i < maxStringLength; i++) {
            formatSpace += "0";
        }

        long v = value;
        if (v < 0) {
            v = -v;
        }
        str = "" + v;
        if (maxStringLength < str.length()) {
            return str;
        }

        return formatSpace.substring(str.length()) + str;
    }

    public static byte[] bit2HexByte(String bitString, int bitNum) {
        int bNum = bitNum / 8;
        if (bitNum % 8 != 0 || bNum <= 0) return null;

        try {
            byte[] hexRet = new byte[bNum];
            for (int k = 0; k < bNum; k++) {
                String str = bitString.substring(k * 8, k * 8 + 8);

                byte result = 0;
                for (int i = str.length() - 1, j = 0; i >= 0; i--, j++) {
                    result += (Byte.parseByte(str.charAt(i) + "") * Math.pow(2, j));
                }

                hexRet[k] = result;
            }

            return hexRet;
        } catch (Exception e) {
        }
        return null;
    }

    public static byte[] subBytes(byte[] data, int offset, int len) {
        if (data == null || data.length <= 0 || offset < 0 || len <= 0 || offset > data.length) {
            return null;
        }

        try {
            if (data.length < offset + len) {
                len = data.length - offset;
            }
            byte[] ret = new byte[len];
            System.arraycopy(data, offset, ret, 0, len);
            return ret;
        } catch (Exception e) {
        }
        return null;
    }

    public static byte[] mergeBytes(byte[] bytesA, byte[] bytesB) {

        if (bytesA == null || bytesA.length == 0) {
            return bytesB;
        } else if (bytesB == null || bytesB.length == 0) {
            return bytesA;
        }

        byte[] bytes = new byte[bytesA.length + bytesB.length];
        System.arraycopy(bytesA, 0, bytes, 0, bytesA.length);
        System.arraycopy(bytesB, 0, bytes, bytesA.length, bytesB.length);
        return bytes;
    }

    public static byte[] gbk2Byte(String str) {
        if (str == null || str.length() <= 0) {
            return null;
        }
        try {
            return str.getBytes("gbk");
        } catch (UnsupportedEncodingException localUnsupportedEncodingException) {
        }
        return null;
    }

    public static String byte2GBK(byte[] strData) {
        if (strData == null || strData.length <= 0) {
            return null;
        }
        try {
            return new String(strData, "gbk");
        } catch (UnsupportedEncodingException localUnsupportedEncodingException) {
        }
        return null;
    }

    public static String trimChar(String orgString, char trim) {
        if (orgString == null || orgString.length() <= 0) {
            return null;
        }
        try {
            String str = String.format("%c", trim);
            if (orgString.endsWith(str)) {
                int i = orgString.length();
                while (--i > 0) {
                    if (orgString.charAt(i) != trim) {
                        return orgString.substring(0, i + 1);
                    }
                }
                return orgString.substring(0, orgString.length() - 1);
            }
            return orgString;
        } catch (Exception e) {
        }
        return null;
    }

    public static String getSystemDatetime() {
        try {
            Calendar c = Calendar.getInstance();
            int y = c.get(Calendar.YEAR);
            int m = c.get(Calendar.MONTH) + 1;
            int d = c.get(Calendar.DAY_OF_MONTH);
            //int w = c.get(Calendar.DAY_OF_WEEK);
            int h = c.get(Calendar.HOUR_OF_DAY);
            int mn = c.get(Calendar.MINUTE);
            int s = c.get(Calendar.SECOND);
            LogUtil.d(TAG, String.format("%04d%02d%02d%02d%02d%02d", y, m, d, h, mn, s));
            return String.format("%04d%02d%02d%02d%02d%02d", y, m, d, h, mn, s);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String getFormatSystemDatetime() {
        try {
            Calendar c = Calendar.getInstance();
            int y = c.get(Calendar.YEAR);
            int m = c.get(Calendar.MONTH) + 1;
            int d = c.get(Calendar.DAY_OF_MONTH);
            //int w = c.get(Calendar.DAY_OF_WEEK);
            int h = c.get(Calendar.HOUR_OF_DAY);
            int mn = c.get(Calendar.MINUTE);
            int s = c.get(Calendar.SECOND);

            return String.format("%04d-%02d-%02d %02d:%02d:%02d", y, m, d, h, mn, s);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String getSystemYear() {
        String dt = getSystemDatetime();
        if (dt != null && dt.length() > 4) {
            return dt.substring(0, 4);
        }
        return null;
    }

    public static String getSystemDate() {
        String dt = getSystemDatetime();
        if (dt != null && dt.length() > 8) {
            return dt.substring(0, 8);
        }
        return null;
    }

    public static String getTransSystemDate() {
        String dt = getSystemDatetime();
        if (dt != null && dt.length() > 8) {
            return dt.substring(4, 8);
        }
        return null;
    }

    public static String getTransSystemTime() {
        String dt = getSystemDatetime();
        if (dt != null && dt.length() > 14) {
            return dt.substring(8, 14);
        }
        return null;
    }

    public static long formatString2Long(String amount) {
        if (amount == null) {
            return 0;
        } else {
            return Long.parseLong(amount);
        }
    }

    public static String getFormattedDateTime(String dataTime, String oldFormat, String newFormat) {
        try {
            return (new SimpleDateFormat(newFormat)).format((new SimpleDateFormat(oldFormat)).parse(dataTime));
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String addPadding(String src, boolean isLeft, char padding, int fixLen) {
        if (src.length() >= fixLen) {
            return src;
        } else {
            StringBuilder b = new StringBuilder();
            int padLen = fixLen - src.length();
            for (int i = 0; i < padLen; ++i) {
                b.append(padding);
            }
            if (isLeft) {
                b.append(src);
            } else {
                b.insert(0, src);
            }
            return b.toString();
        }
    }

    public static String getHash(String sha1Data) {
        MessageDigest md = null;
        String outStr = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(Utils.hexStr2Bytes(sha1Data));
            outStr = byte2Str(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return outStr;
    }

    public static String getReadableAmount(String amount) {
        if (amount != null && amount.length() > 0) {
            char c;
            for (int i = 0; i < amount.length(); i++) {
                c = amount.charAt(i);
                if (c < '0' || c > '9') {
                    return "0.00";
                }
            }
            DecimalFormat df = new DecimalFormat("0.00");
            return df.format(Double.parseDouble(amount) / 100.0D);
        } else {
            return "0.00";
        }
    }

    public static String callCmd(String cmd, String filter) {
        String result = "";
        String line = "";
        try {
            Process proc = Runtime.getRuntime().exec(cmd);
            InputStreamReader is = new InputStreamReader(proc.getInputStream());
            BufferedReader br = new BufferedReader(is);

            //执行命令cmd，只取结果中含有filter的这一行
            while ((line = br.readLine()) != null && line.contains(filter) == false) {
            }

            result = line;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static boolean isChinese(char c) {
        String chinese = "[\u4e00-\u9fa5]";
        String tmp = "" + c;
        if (tmp.matches(chinese)) {
            return true;
        } else {
            return false;
        }
    }

    public static String mask(String value, String mask) {
        int markStart = -1;

        int markEnd;
        for (markEnd = 0; markEnd < mask.length(); ++markEnd) {
            if (mask.charAt(markEnd) == 42) {
                markStart = markEnd;
                break;
            }

            if (mask.charAt(markEnd) != 120 && mask.charAt(markEnd) != 88) {
                markStart = markEnd;
                break;
            }
        }

        if (markStart != -1 && markStart < value.length()) {
            markEnd = markStart + 1;

            for (int str = mask.length() - 1; str > markStart + 1; --str) {
                if (mask.charAt(str) == 42) {
                    markEnd = str + 1;
                    break;
                }

                if (mask.charAt(str) != 120 && mask.charAt(str) != 88) {
                    markEnd = str + 1;
                    break;
                }
            }

            if (mask.length() - markEnd + markStart >= value.length()) {
                return value;
            } else {
                StringBuilder var6 = new StringBuilder();
                var6.append(value.substring(0, markStart));
                markEnd += value.length() - mask.length();

                for (int i = markStart; i < markEnd; ++i) {
                    var6.append("*");
                }

                if (markEnd < value.length()) {
                    var6.append(value.substring(markEnd));
                }

                return var6.toString();
            }
        } else {
            return value;
        }
    }

    public static String getRandom(int length) {
        String ret = "";
        for (int i = 0; i < length; i++) {
            java.util.Random random = new java.util.Random();
            ret += random.nextInt(10);
        }
        return ret;
    }

    private static byte[] findedTag;
    private static byte[] findTagValue;
    private static int findTagLength;

    public static byte[] findTag(String tag, byte[] buffer, int bufferLength) {
        if (tag == null || buffer == null || bufferLength <= 0) {
            return null;
        }

        byte[] ptr;
        byte[] findTag = Utils.asc2Bcd(tag);
        int bytesRead;

        bytesRead = 0;
        do {
            ptr = Utils.subBytes(buffer, bytesRead, buffer.length - bytesRead);
            if (ptr == null) {
                break;
            }
            bytesRead += findTag_getNextTLVObject(ptr);
            if (Arrays.equals(findTag, findedTag)) {
                if (findTagValue == null) {
                    return null;
                } else if (findTagValue.length <= findTagLength) {
                    return findTagValue;
                } else {
                    return Utils.subBytes(findTagValue, 0, findTagLength);
                }
            }
        } while (bytesRead < bufferLength);

        return null;
    }

    public static String findTag(String tag, String string) {
        if (tag == null || string == null || string.length() <= 0) {
            return null;
        }

        byte[] ptr;
        byte[] findTag = Utils.asc2Bcd(tag);
        byte[] buffer = Utils.asc2Bcd(string);
        int bytesRead;
        int length = buffer.length;

        bytesRead = 0;
        do {
            ptr = Utils.subBytes(buffer, bytesRead, length - bytesRead);
            if (ptr == null) {
                break;
            }
            bytesRead += findTag_getNextTLVObject(ptr);
            if (Arrays.equals(findTag, findedTag)) {
                return Utils.bcd2Asc(findTagValue, findTagLength);
            }
        } while (bytesRead < length);

        return null;
    }

    private static int findTag_getNextTLVObject(byte[] buffer) {
        byte[] ptr;
        byte tagByte1;
        int numLengthBytes;
        int dataLength;
        int i;
        int numTagBytes;
        int bytesRead;
        ptr = Utils.subBytes(buffer, 0, buffer.length);
//		Log.i(TAG, "ptr=" + Utils.bcd2Asc(ptr));
        tagByte1 = ptr[0];
        if ((tagByte1 & 0x1F) == 0x1F) {
            findedTag = new byte[2];
            findedTag = Utils.subBytes(ptr, 0, 2);
            numTagBytes = 2;
        } else {
            findedTag = new byte[1];
            findedTag = Utils.subBytes(ptr, 0, 1);
            numTagBytes = 1;
        }
//		Log.i(TAG, "tag=" + Utils.bcd2Asc(findedTag) );

        numLengthBytes = 1;
        dataLength = ptr[numTagBytes] & 0xFF;
        findTagLength = dataLength;
//		Log.i(TAG, "length=" + findTagLength );
        findTagValue = Utils.subBytes(ptr, numTagBytes + 1, dataLength);
//		Log.i(TAG, "value=" + Utils.bcd2Asc(findTagValue) );
        bytesRead = numTagBytes + numLengthBytes + dataLength;
        return (bytesRead);
    }

    public static int getChineseCharNum(String str) {
        int count = 0;
        char[] chars = str.toCharArray();
        for (char c : chars) {
            if (isChineseByBlock(c)) {
                count++;
            }
            if (isChinesePunctuation(c)) {
                count++;
            }
        }
        return count;

    }

    //使用UnicodeBlock方法判断
    public static boolean isChineseByBlock(char c) {
        Character.UnicodeBlock ub = Character.UnicodeBlock.of(c);
        if (ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS
                || ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A
                || ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_B
                || ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_C
                || ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_D
                || ub == Character.UnicodeBlock.CJK_COMPATIBILITY_IDEOGRAPHS
                || ub == Character.UnicodeBlock.CJK_COMPATIBILITY_IDEOGRAPHS_SUPPLEMENT) {
            return true;
        } else {
            return false;
        }
    }

    // 根据UnicodeBlock方法判断中文标点符号
    public static boolean isChinesePunctuation(char c) {
        Character.UnicodeBlock ub = Character.UnicodeBlock.of(c);
        if (ub == Character.UnicodeBlock.GENERAL_PUNCTUATION
                || ub == Character.UnicodeBlock.CJK_SYMBOLS_AND_PUNCTUATION
                || ub == Character.UnicodeBlock.HALFWIDTH_AND_FULLWIDTH_FORMS
                || ub == Character.UnicodeBlock.CJK_COMPATIBILITY_FORMS
                || ub == Character.UnicodeBlock.VERTICAL_FORMS) {
            return true;
        } else {
            return false;
        }
    }


    //获取0的字符串
    public static String getZero(int length) {
        String str = "";
        for (int i = 0; i < length; i++) {
            str += "0";
        }
        return str;
    }

    /**
     * 左侧补零
     * length  返回字符串长度
     * s的长度超过length,返回s;小于length，左侧不足补零
     */
    public static String leftZeroShift(String s, int length) {
        if (s == null || s.length() > length)
            return s;
        String str = getZero(length) + s;
        str = str.substring(str.length() - length);
        return str;
    }

    /**
     * 右侧补零
     * length  返回字符串长度
     * s的长度超过length,返回s;小于length，右侧不足补零
     */
    public static String rightZeroShift(String s, int length) {
        if (s == null || s.length() > length)
            return s;
        String str = s + getZero(length);
        str = str.substring(0, length);
        return str;
    }

    public static String formatAmount(String amount) {
        if (amount == null) {
            return "0.00";
        } else {
            return String.format("%.2f", Double.parseDouble(amount) / 100.00);
        }
    }

    public static double formatString2Double(String amount) {
        if (amount == null) {
            return 0.00;
        } else {
            return Double.parseDouble(amount) / 100.00;
        }
    }

    /**
     * 验证日期是否合法
     *
     * @param dateStr 日期字符串(例如"20180508")
     * @return 合法返回true, 不合法返回false
     */
    public static boolean isDateLegal(String dateStr) {
        // 如果日期不合法，则抛异常
        System.out.println("isDateLegal 验证日期合法性：" + dateStr);

        if (dateStr == null || dateStr.length() < 8)
            return false;

        try {
            SimpleDateFormat format = new SimpleDateFormat("yyyyMMdd");
            format.setLenient(false);
            //Date date = format.parse(dateStr);
            Date date = format.parse(dateStr);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("isDateLegal 日期不合法");
            return false;
        }

        return true;
    }

}
