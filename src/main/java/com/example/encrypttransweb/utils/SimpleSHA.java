package com.example.encrypttransweb.utils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * SHA-256 算法简易版实现
 * <p>
 * 基本原理：
 *  SHA256 是个 Hash 算法，和最常听说的 MD5 一样，就是将任意长度的输入内容，转换成固定长度的输出散列值。
 *      这个输出的长度 SHA256 就是 256 位，也就是 256 / 8 = 32 个字节
 *      特点和 MD5 等其他 Hash 算法一样，只不过具体 Hash 算法不同，强度也不同：
 *          1. 不可逆
 *          2. 雪崩效应（微小的变化会导致输出截然不同）
 *          3. 抗碰撞性
 * <p>
 * 基本步骤
 *  1. 消息填充。将输入填充到模 512 的余数为 448 位（padMessage 方法）,填充完成的消息末尾附加上原始消息的长度。
 *      填充方式：加一个 1 位 和 n 个 0 位
 *
 *      为什么要填充 1 个 1 和 n 个 0？
 *          填充 1 是为了标记消息结束。
 *              有人疑惑末尾本来就是 1 怎么区分是标记？动动脑，反正我都是要加个 1 来区分，管它末尾是 0 还是 1，最后一个 1 就是结束标志，因为结束标志符 1 后面全是 0 来填充补位
 *          填充 n 个 0 是为了保证消息块大小，因为 SHA256 的消息块大小是 512 ，但是最后要附加消息长度是 64 位，所以要填充到 模 512 的余数为 448，然后加上消息长度 64，最后就刚好可以满足 512 的倍数
 *
 *      以 “Hello SHA256” 字符串为例：
 *      0x48 0x65 0x6C 0x6C 0x6F 0x20 0x53 0x48 0x41 0x32 0x35 0x36
 *
 *      转为 2 进制 bit 流
 *      01001000 01100101 01101100 01101100 01101111 00100000 01010011 01001000 01000001 00110010 00110101 00110110
 *
 *      加上 1 比特，即 0x80 作为结束标志
 *      01001000 01100101 01101100 01101100 01101111 00100000 01010011 01001000 01000001 00110010 00110101 00110110 10000000
 *
 *      再加 43 个 0 填充，使其满足位数 模 512 余 448（也就是字节模 64 余 56）
 *      源数据长度 12 字节 + 结束标识 1，为 13 字节，要满足 模 64 余 56， 就需要填充 56 - 13 = 43 个字节，也就是 43 * 8 个 0 位
 *
 *      00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 *      00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 *      00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 *      00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 *      00000000 00000000 00000000
 *
 *      然后，再填充上原始消息长度，12 字节 * 8 = 96 位，转成 8 字节的 64 位二进制，也就是
 *      00000000 00000000 00000000 00000000 00000000 00000000 00000000 01100000
 *
 *      最终合起来的填充结果就是
 *      01001000 01100101 01101100 01101100 01101111 00100000 01010011 01001000 01000001 00110010 00110101 00110110 10000000
 *      00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 *      00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 *      00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 *      00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 *      00000000 00000000 00000000
 *      00000000 00000000 00000000 00000000 00000000 00000000 00000000 01100000
 * <p>
 *  2. 初始化缓冲区。生成 8 个 32 位的初始哈希
 *      8 个缓冲区，也就是代码中的 H0-H7， 下面注释中也有说明，这是算法固定的值，来源于前 8 个素数的平方根的前 32 位小数部分*
 * <p>
 *  3. 消息分块。就是将填充之后的消息按照 512 位的大小分成块，由于上一步加上最后的 64 位长度，已经填充为 512 的倍数了，所以直接拆分就行
 *      但是我们这个测试消息太短了，填充完成后也就刚好满足一个 512 长度，所以都不需要拆分。
 * <p>
 *      PS：不要好奇为什么 SHA256 的消息块长度是 512，SHA512 的消息块长度是 1028，这个是基于速度和安全性共同考虑的选择，
 *      这里 SHA256 名称中 256 指的是最终生成的 Hash 长度为 256 位，也就是 32 字节
 *      但是这个命名只是个参考，不具备绝对性，就比如 SHA-1 结果长度也不可能是 1 位，它是 160 位
 * <p>
 *  4. 消息压缩。对每一个 512 位消息块进行压缩（64 轮）
 *       消息压缩循环（算法最核心的处理过程）
 *              大致过程：
 *              对第 0 个和第 4 个 Hash 值（也就是 a 和 e，它们每层迭代都在变化的）进行旋转位移操作。（增加非线性）
 *              对 e 的处理结果，结合 f 和 g，这 3 个 Hash 运行选择函数（也就是 ch 变量。根据 e 的值，从 f 和 g 中选择一个输出）
 *              对 a 的处理结果，结合 b 和 c，这 3 个 Hash 运行多数函数（也就是 maj 变量。输出 a、b、c 三个数的出现最多的位）
 *              以上这两步操作，是 Hash 算法的不可逆性质的关键。
 *               简单说，从两个已知的数中根据规则得到一个数简单，但是根据结果想要逆推出两个数，那可能性就太多了
 *               多数函数更容易理解，a、b、c 三个数中出现最多的位
 *                   比如第 0 位出现最多的是 1，第 1 位出现最多的是 0，第 2 位出现最多的是 0，
 *                   只知道每一位出现最多的数字，那是 3 个 256 位的数字对比的结果，还经过多轮迭代，逆推是完全不现实的。
 *              最后一步计算就是简单的计算，h 和 w 两个 Hash 加上当前迭代轮的常量 K 再加上前两步的计算结果，得到两个临时值
 *              然后按照规则，将这两个临时值和前面计算得到的其他 Hash 值依次更新
 *
 *  6. 生成最终哈希。所有块处理完之后，缓冲区中的值就是最终哈希值
 */
public class SimpleSHA {
    // 常量 K 数组，64 个 32 位常量
    /**
     * 这 64 个数字是固定的，来源于 前 64 个素数的立方根的小数部分的前 32 位
     * 主要作用是在算法的每一轮中作为 64 次混合运算的每一次的常量，可以理解为第几轮运算的标识，确保散列值的高熵性和抗碰撞性
      */
    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    // 初始哈希值 H0 到 H7
    /**
     * 这 8 个常量也是固定的，来源于前 8 个素数的平方根的小数部分的前 32 位。
     * 主要作用是在算法开始时用于初始化哈希缓冲区，并在 512 位消息块处理过程中不断更新，形成最终的散列值
     */
    private static final int H0 = 0x6a09e667;
    private static final int H1 = 0xbb67ae85;
    private static final int H2 = 0x3c6ef372;
    private static final int H3 = 0xa54ff53a;
    private static final int H4 = 0x510e527f;
    private static final int H5 = 0x9b05688c;
    private static final int H6 = 0x1f83d9ab;
    private static final int H7 = 0x5be0cd19;

    /**
     * 计算 SHA-256 哈希值
     * @param input 输入的字节数组
     * @return 哈希值的字节数组
     */
    public static byte[] sha256(byte[] input) {
        // 初始化哈希值
        int[] h = {H0, H1, H2, H3, H4, H5, H6, H7};

        // 对消息进行填充
        byte[] padded = padMessage(input);
        int[] w = new int[64];

        // 将填充后的消息拆分成 64 个字节（512位）大小的消息块，并单独处理
        for (int i = 0; i < padded.length; i += 64) {
            // 每个消息块再次分别处理
            // 将消息块再次拆分成 16 个 4 字节的小块，然后对其进行拼合，组成 16 个 32 位的整数
            for (int t = 0; t < 16; t++) {
                w[t] = ((padded[i + t * 4] & 0xFF) << 24) | ((padded[i + t * 4 + 1] & 0xFF) << 16) |
                        ((padded[i + t * 4 + 2] & 0xFF) << 8) | (padded[i + t * 4 + 3] & 0xFF);
            }
            // 扩展消息块，将上面生成的 16 个 32 位整数通过旋转、位移等操作扩展为 64 个 32 为整数
            // 从这里开始，非线性函数扩展消息块的主要目的就是 增加 数据之间的混淆性，增强散列函数的抗碰撞性
            for (int t = 16; t < 64; t++) {
                int s0 = Integer.rotateRight(w[t - 15], 7) ^ Integer.rotateRight(w[t - 15], 18) ^ (w[t - 15] >>> 3);
                int s1 = Integer.rotateRight(w[t - 2], 17) ^ Integer.rotateRight(w[t - 2], 19) ^ (w[t - 2] >>> 10);
                w[t] = w[t - 16] + s0 + w[t - 7] + s1;
            }

            // 初始化工作变量，也就是最初始的 hash 值，接下来的消息压缩操作的就是使用算法不停的更新原始的 hash 值
            // 这也是为什么不论原始消息长度为多少，经过 SHA256 处理之后的结果长度都是固定的 256 位的原因
            int a = h[0];
            int b = h[1];
            int c = h[2];
            int d = h[3];
            int e = h[4];
            int f = h[5];
            int g = h[6];
            int hh = h[7];

            // 消息压缩循环（算法最核心的处理过程）
            // 大致过程：
            // 对第 0 个和第 4 个 Hash 值（也就是 a 和 e，它们每层迭代都在变化的）进行旋转位移操作。（增加非线性）
            // 对 e 的处理结果，结合 f 和 g，这 3 个 Hash 运行选择函数（也就是 ch 变量。根据 e 的值，从 f 和 g 中选择一个输出）
            // 对 a 的处理结果，结合 b 和 c，这 3 个 Hash 运行多数函数（也就是 maj 变量。输出 a、b、c 三个数的出现最多的位）
            // 以上这两步操作，是 Hash 算法的不可逆性质的关键。
            //  简单说，从两个已知的数中根据规则得到一个数简单，但是根据结果想要逆推出两个数，那可能性就太多了
            //  多数函数更容易理解，a、b、c 三个数中出现最多的位
            //      比如第 0 位出现最多的是 1，第 1 位出现最多的是 0，第 2 位出现最多的是 0，
            //      只知道每一位出现最多的数字，那是 3 个 256 位的数字对比的结果，还经过多轮迭代，逆推是完全不现实的。
            // 最后一步计算就是简单的计算，
            //  h（由于命名和冲突，也就是下面的 hh） 和 w 两个 Hash 加上当前迭代轮的常量 K 再加上前两步的计算结果，得到一个临时值
            //  多数函数的结果和 S0 组成第二个临时变量
            // 然后按照规则，将这两个临时值和前面计算得到的其他 Hash 值依次更新
            for (int t = 0; t < 64; t++) {
                int S1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
                int ch = (e & f) ^ ((~e) & g);
                int temp1 = hh + S1 + ch + K[t] + w[t];
                int S0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
                int maj = (a & b) ^ (a & c) ^ (b & c);
                int temp2 = S0 + maj;

                hh = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            // 每次循环结束，更新哈希值
            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
            h[5] += f;
            h[6] += g;
            h[7] += hh;
        }

        // 生成最终的哈希值
        byte[] hash = new byte[32];
        for (int i = 0; i < 8; i++) {
            hash[i * 4] = (byte) ((h[i] >> 24) & 0xFF);
            hash[i * 4 + 1] = (byte) ((h[i] >> 16) & 0xFF);
            hash[i * 4 + 2] = (byte) ((h[i] >> 8) & 0xFF);
            hash[i * 4 + 3] = (byte) (h[i] & 0xFF);
        }

        return hash;
    }

    /**
     * 对消息进行填充
     * @param input 输入的字节数组
     * @return 填充后的字节数组
     */
    private static byte[] padMessage(byte[] input) {
        int originalLength = input.length;
        int padLength = 64 - (originalLength % 64);
        if (padLength < 9) padLength += 64;

        byte[] padded = Arrays.copyOf(input, originalLength + padLength);
        padded[originalLength] = (byte) 0x80;

        long bitLength = (long) originalLength * 8;
        for (int i = 0; i < 8; i++) {
            padded[padded.length - 1 - i] = (byte) (bitLength >>> (i * 8));
        }

        return padded;
    }

    /**
     * 将字节数组转换为十六进制字符串
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * 测试类
     * @param args
     */
    public static void main(String[] args) {
        String message = "Hello SHA256";
        byte[] hash = sha256(message.getBytes(StandardCharsets.UTF_8));
        System.out.println("Hash: " + bytesToHex(hash));
    }
}
