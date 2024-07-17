package com.example.encrypttransweb.utils;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * RSA 1024 算法简易版实现
 * 这些简易版本的，只是方便看清原理，与标准 RSA 加密存在区别的
 *
 * 基本原理：
 *
 */
public class SimpleRSA {

    // 定义 n 为模数, d 为私钥, e 为公钥
    private BigInteger n, d, e;
    // 以 RSA 1024 为例，密钥长度 1024
    private int bitlen = 1024;

    public SimpleRSA(int bits) {
        bitlen = bits;
    }

    /**
     * 加密
     * @param message 要加密的信息
     * @param publicKey 公钥
     * @param modulus 模数
     * @return 加密后的字节数组
     */
    public static synchronized byte[] encrypt(byte[] message, BigInteger publicKey, BigInteger modulus) {
        // 将字节数组转换为正整数
        BigInteger plaintext = new BigInteger(1, message);
        // 使用公钥和模数进行加密
        BigInteger ciphertext = plaintext.modPow(publicKey, modulus);
        // 返回加密后的字节数组
        return ciphertext.toByteArray();
    }

    /**
     * 解密
     * @param message 要解密的信息
     * @param privateKey 私钥
     * @param modulus 模数
     * @return 解密后的字节数组
     */
    public static synchronized byte[] decrypt(byte[] message, BigInteger privateKey, BigInteger modulus) {
        // 将字节数组转换为正整数
        BigInteger ciphertext = new BigInteger(1, message);
        // 使用私钥和模数进行解密
        BigInteger plaintext = ciphertext.modPow(privateKey, modulus);
        // 解密后的字节数组
        byte[] plaintextArray = plaintext.toByteArray();

        // 去除前导的0字节
        if (plaintextArray[0] == 0) {
            byte[] truncatedArray = new byte[plaintextArray.length - 1];
            System.arraycopy(plaintextArray, 1, truncatedArray, 0, truncatedArray.length);
            return truncatedArray;
        }
        return plaintextArray;
    }

    /**
     * 初始化公私钥
     * @throws IOException
     */
    public synchronized void initializeRSA() throws IOException {
        SecureRandom r = new SecureRandom();
        // 生成大素数 p
        BigInteger p = BigInteger.probablePrime(bitlen / 2, r);
        // 生成大素数 q
        BigInteger q = BigInteger.probablePrime(bitlen / 2, r);
        // n = p * q
        n = p.multiply(q);
        // 欧拉函数 m = (p-1)*(q-1)
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        // 公钥 e 一般选用常数 65537
        e = new BigInteger("65537");
        // 私钥 d 为 e 在模 m 下的逆
        d = e.modInverse(m);

        // 创建密钥存储目录
        Files.createDirectories(Paths.get("keys"));

        // 将公私钥写入本地存储
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("keys/rsa.public.key"))) {
            oos.writeObject(e);
            oos.writeObject(n);
        }

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("keys/rsa.private.key"))) {
            oos.writeObject(d);
            oos.writeObject(n);
        }
    }

    /**
     * 读取公钥
     * @return 公钥数组 [e, n]
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static BigInteger[] readPublicKey() throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("keys/rsa.public.key"))) {
            // 读取公钥
            BigInteger e = (BigInteger) ois.readObject();
            // 读取模数
            BigInteger n = (BigInteger) ois.readObject();
            return new BigInteger[]{e, n};
        }
    }

    /**
     * 读取私钥
     * @return 私钥数组 [d, n]
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static BigInteger[] readPrivateKey() throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("keys/rsa.private.key"))) {
            BigInteger d = (BigInteger) ois.readObject();
            BigInteger n = (BigInteger) ois.readObject();
            return new BigInteger[]{d, n};
        }
    }

    /**
     * 测试类
     * @param args
     */
    public static void main(String[] args) {
        try {
            byte[] text1 = new byte[]{-103, 55, -27, 98, 68, -50, 114, 72, 74, 121, -44, -11, -8, -102, -120, 28};
            System.out.println("Plaintext: " + Arrays.toString(text1));

            // Read public key
            BigInteger[] publicKey = readPublicKey();
            byte[] ciphertext = encrypt(text1, publicKey[0], publicKey[1]);
            System.out.println("Ciphertext: " + Arrays.toString(ciphertext));

            // Read private key
            BigInteger[] privateKey = readPrivateKey();
            byte[] plaintext = decrypt(ciphertext, privateKey[0], privateKey[1]);
            System.out.println("Decrypted: " + Arrays.toString(plaintext));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
