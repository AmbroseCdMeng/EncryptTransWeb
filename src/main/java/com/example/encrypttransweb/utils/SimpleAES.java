package com.example.encrypttransweb.utils;

import java.util.Arrays;
import java.util.Random;

/**
 * AES CBC 简易实现
 * 这些简易版本的，只是方便看清原理，与标准 AES 加密还是有点区别的
 * AES 算法还是比较复杂的，这里只实现 CBC 加密模式
 */
public class SimpleAES {

    private static final int BLOCK_SIZE = 16;
    private static final int ROUNDS = 10;
    private static final int[] INV_S_BOX = new int[256];
    private static final int[] S_BOX = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    private static final int[] RCON = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    public static final int PADDING_CBC = 0;
    public static final int PADDING_NONE = 1;

    private static int paddingMode = PADDING_CBC;

    static {
        for (int i = 0; i < 256; i++) {
            INV_S_BOX[S_BOX[i]] = i;
        }
    }

    /**
     * 代换字节
     *
     * @param state
     */
    private static void subBytes(int[] state) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] = S_BOX[state[i] & 0xff];
        }
    }

    /**
     * 行位移
     *
     * @param state
     */
    private static void shiftRows(int[] state) {
        int[] temp = new int[BLOCK_SIZE];

        System.arraycopy(state, 0, temp, 0, 4);

        temp[4] = state[5];
        temp[5] = state[6];
        temp[6] = state[7];
        temp[7] = state[4];

        temp[8] = state[10];
        temp[9] = state[11];
        temp[10] = state[8];
        temp[11] = state[9];

        temp[12] = state[15];
        temp[13] = state[12];
        temp[14] = state[13];
        temp[15] = state[14];

        System.arraycopy(temp, 0, state, 0, BLOCK_SIZE);
    }

    /**
     * 混合列
     *
     * @param state
     */
    private static void mixColumns(int[] state) {
        for (int i = 0; i < 4; i++) {
            int start = i * 4;
            int a0 = state[start];
            int a1 = state[start + 1];
            int a2 = state[start + 2];
            int a3 = state[start + 3];

            state[start] = (mul2(a0) ^ mul3(a1) ^ a2 ^ a3) & 0xff;
            state[start + 1] = (a0 ^ mul2(a1) ^ mul3(a2) ^ a3) & 0xff;
            state[start + 2] = (a0 ^ a1 ^ mul2(a2) ^ mul3(a3)) & 0xff;
            state[start + 3] = (mul3(a0) ^ a1 ^ a2 ^ mul2(a3)) & 0xff;
        }
    }

    private static int mul2(int value) {
        return ((value << 1) & 0xff) ^ (((value >> 7) & 1) * 0x1b);
    }

    private static int mul3(int value) {
        return mul2(value) ^ value;
    }

    private static int mul9(int value) {
        return mul2(mul2(mul2(value))) ^ value;
    }

    private static int mul11(int value) {
        return mul2(mul2(mul2(value)) ^ value) ^ value;
    }

    private static int mul13(int value) {
        return mul2(mul2(mul2(value) ^ value)) ^ value;
    }

    private static int mul14(int value) {
        return mul2(mul2(mul2(value) ^ value) ^ value);
    }

    /**
     * 轮密钥加
     *
     * @param state
     * @param roundKey
     */
    private static void addRoundKey(int[] state, int[] roundKey) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] ^= roundKey[i];
        }
    }

    /**
     * 扩展密钥
     *
     * @param key
     * @return
     */
    private static int[] keyExpansion(byte[] key) {
        int[] expandedKey = new int[BLOCK_SIZE * (ROUNDS + 1)];
        int temp;
        int i = 0;

        for (i = 0; i < key.length; i++) {
            expandedKey[i] = key[i] & 0xff;
        }

        for (; i < expandedKey.length; i++) {
            temp = expandedKey[i - 1];
            if (i % key.length == 0) {
                temp = subWord(rotWord(temp)) ^ RCON[(i / key.length) - 1];
            } else if (key.length > 6 && (i % key.length == 4)) {
                temp = subWord(temp);
            }
            expandedKey[i] = expandedKey[i - key.length] ^ temp;
        }

        return expandedKey;
    }

    /**
     * S-盒替换字
     *
     * @param word
     * @return
     */
    private static int subWord(int word) {
        return (S_BOX[(word >> 24) & 0xff] << 24) |
                (S_BOX[(word >> 16) & 0xff] << 16) |
                (S_BOX[(word >> 8) & 0xff] << 8) |
                S_BOX[word & 0xff];
    }

    /**
     * 旋转字
     *
     * @param word
     * @return
     */
    private static int rotWord(int word) {
        return ((word << 8)) | ((word >> 24) & 0xff);
    }

    /**
     * 逆S-盒替换
     *
     * @param state
     */
    private static void invSubBytes(int[] state) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] = INV_S_BOX[state[i] & 0xff];
        }
    }

    /**
     * 逆行移位操作
     *
     * @param state
     */
    private static void invShiftRows(int[] state) {
        int[] temp = new int[BLOCK_SIZE];

        System.arraycopy(state, 0, temp, 0, 4);

        temp[4] = state[7];
        temp[5] = state[4];
        temp[6] = state[5];
        temp[7] = state[6];

        temp[8] = state[10];
        temp[9] = state[11];
        temp[10] = state[8];
        temp[11] = state[9];

        temp[12] = state[13];
        temp[13] = state[14];
        temp[14] = state[15];
        temp[15] = state[12];

        System.arraycopy(temp, 0, state, 0, BLOCK_SIZE);
    }

    /**
     * 逆列混合
     *
     * @param state
     */
    private static void invMixColumns(int[] state) {
        for (int i = 0; i < 4; i++) {
            int start = i * 4;
            int a0 = state[start];
            int a1 = state[start + 1];
            int a2 = state[start + 2];
            int a3 = state[start + 3];

            state[start] = (mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3)) & 0xff;
            state[start + 1] = (mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3)) & 0xff;
            state[start + 2] = (mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3)) & 0xff;
            state[start + 3] = (mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3)) & 0xff;
        }
    }


    public static byte[] generateRandomKey() {
        byte[] key = new byte[16];
        new Random().nextBytes(key);
        return key;
    }

    public static byte[] pad(byte[] input) {
        if (paddingMode == PADDING_NONE) {
            return input;
        }
        int paddingLength = BLOCK_SIZE - (input.length % BLOCK_SIZE);
        byte[] padded = new byte[input.length + paddingLength];
        System.arraycopy(input, 0, padded, 0, input.length);
        Arrays.fill(padded, input.length, padded.length, (byte) paddingLength);
        return padded;
    }

    public static byte[] unpad(byte[] input) {
        if (paddingMode == PADDING_NONE) {
            return input;
        }
        int paddingLength = input[input.length - 1];
        byte[] unpadded = new byte[input.length - paddingLength];
        System.arraycopy(input, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }

    public static byte[] encrypt(byte[] input, byte[] key) {
        input = pad(input);
        int numBlocks = input.length / BLOCK_SIZE;
        byte[] output = new byte[input.length];

        for (int block = 0; block < numBlocks; block++) {
            int[] state = new int[BLOCK_SIZE];
            int[] expandedKey = keyExpansion(key);

            for (int i = 0; i < BLOCK_SIZE; i++) {
                state[i] = input[block * BLOCK_SIZE + i] & 0xff;
            }
            addRoundKey(state, Arrays.copyOfRange(expandedKey, 0, BLOCK_SIZE));

            for (int round = 1; round < ROUNDS; round++) {
                subBytes(state);
                shiftRows(state);
                mixColumns(state);
                addRoundKey(state, Arrays.copyOfRange(expandedKey, round * BLOCK_SIZE, (round + 1) * BLOCK_SIZE));
            }

            subBytes(state);
            shiftRows(state);
            addRoundKey(state, Arrays.copyOfRange(expandedKey, ROUNDS * BLOCK_SIZE, (ROUNDS + 1) * BLOCK_SIZE));

            for (int i = 0; i < BLOCK_SIZE; i++) {
                output[block * BLOCK_SIZE + i] = (byte) state[i];
            }
        }
        return output;
    }

    public static byte[] decrypt(byte[] input, byte[] key) {
        int numBlocks = input.length / BLOCK_SIZE;
        byte[] output = new byte[input.length];

        for (int block = 0; block < numBlocks; block++) {
            int[] state = new int[BLOCK_SIZE];
            int[] expandedKey = keyExpansion(key);

            for (int i = 0; i < BLOCK_SIZE; i++) {
                state[i] = input[block * BLOCK_SIZE + i] & 0xff;
            }
            addRoundKey(state, Arrays.copyOfRange(expandedKey, ROUNDS * BLOCK_SIZE, (ROUNDS + 1) * BLOCK_SIZE));

            for (int round = ROUNDS - 1; round > 0; round--) {
                invShiftRows(state);
                invSubBytes(state);
                addRoundKey(state, Arrays.copyOfRange(expandedKey, round * BLOCK_SIZE, (round + 1) * BLOCK_SIZE));
                invMixColumns(state);
            }

            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, Arrays.copyOfRange(expandedKey, 0, BLOCK_SIZE));

            for (int i = 0; i < BLOCK_SIZE; i++) {
                output[block * BLOCK_SIZE + i] = (byte) state[i];
            }
        }
        return unpad(output);
    }

    public static void setPaddingMode(int mode) {
        paddingMode = mode;
    }

    /**
     * 测试类
     * @param args
     */
    public static void main(String[] args) {

        byte[] key = generateRandomKey();
        System.out.println("key(Hex): " + Arrays.toString(key));
        System.out.println("key: " + SimpleBase64.byteToBase64(key));
        setPaddingMode(PADDING_CBC);
        String plaintext = "Hello, AES encryption with CBC padding!";
        byte[] input = plaintext.getBytes();

        byte[] ciphertext = encrypt(input, key);
        System.out.println("Ciphertext: " + SimpleBase64.byteToBase64(ciphertext));
        System.out.println("Key: " + SimpleBase64.byteToBase64(key));

        byte[] decryptedText = decrypt(ciphertext, key);
        System.out.println("Decrypted text: " + Arrays.toString(decryptedText));
        System.out.println("Decrypted text (as string): " + new String(decryptedText).trim());
    }
}
