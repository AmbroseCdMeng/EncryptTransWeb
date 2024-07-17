package com.example.encrypttransweb.utils;

import java.util.Arrays;

/**
 * Base64 简易版实现。
 * 这些简易版本的，只是方便看清原理，肯定还是存在很多问题的
 */
public class SimpleBase64 {

    private static final char[] encodingTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    public static String byteToBase64(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        int padding = 0;
        for (int i = 0; i < bytes.length; i += 3) {
            int b1 = bytes[i] & 0xFF;
            int b2 = (i + 1 < bytes.length) ? bytes[i + 1] & 0xFF : 0;
            int b3 = (i + 2 < bytes.length) ? bytes[i + 2] & 0xFF : 0;

            int combined = (b1 << 16) | (b2 << 8) | b3;

            result.append(encodingTable[(combined >> 18) & 0x3F]);
            result.append(encodingTable[(combined >> 12) & 0x3F]);
            result.append((i + 1 < bytes.length) ? encodingTable[(combined >> 6) & 0x3F] : '=');
            result.append((i + 2 < bytes.length) ? encodingTable[combined & 0x3F] : '=');
        }

        return result.toString();
    }

    public static byte[] base64ToByte(String base64String) {
        int padding = 0;
        for (int i = base64String.length() - 1; base64String.charAt(i) == '='; i--) {
            padding++;
        }

        int length = base64String.length() * 6 / 8 - padding;
        byte[] result = new byte[length];
        int index = 0;
        int block = 0;
        int blockCount = 0;

        for (int i = 0; i < base64String.length(); i++) {
            char c = base64String.charAt(i);
            int value = (c <= 'Z' && c >= 'A') ? c - 'A'
                    : (c <= 'z' && c >= 'a') ? c - 'a' + 26
                    : (c <= '9' && c >= '0') ? c - '0' + 52
                    : (c == '+') ? 62
                    : (c == '/') ? 63
                    : 0;

            block = (block << 6) + value;
            blockCount++;

            if (blockCount == 4) {
                result[index++] = (byte) (block >> 16);
                if (index < length)
                    result[index++] = (byte) (block >> 8);
                if (index < length)
                    result[index++] = (byte) (block);
                block = 0;
                blockCount = 0;
            }
        }

        return result;
    }

    /**
     * 测试类
     * @param args
     */
    public static void main(String[] args) {
        String text = "lCgzIHEj+XB62f2QwAzEQPWoRY2RXKnji3jXMcE3bRs=";
        byte[] bytes = base64ToByte(text);
        System.out.println(Arrays.toString(bytes));
        String s = byteToBase64(bytes);
        System.out.println(s);
    }
}
