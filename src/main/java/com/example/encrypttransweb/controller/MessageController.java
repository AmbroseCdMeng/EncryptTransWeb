package com.example.encrypttransweb.controller;


import com.example.encrypttransweb.bean.CipherData;
import com.example.encrypttransweb.bean.PlainData;
import com.example.encrypttransweb.utils.SimpleAES;
import com.example.encrypttransweb.utils.SimpleBase64;
import com.example.encrypttransweb.utils.SimpleRSA;
import com.example.encrypttransweb.utils.SimpleSHA;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * 这是专门为 Socket 协议定义的加解密方法，代码逻辑和 Web 接口是一样的，只是为了迎合 WebSocket 通信
 */
@Controller
public class MessageController {
    @MessageMapping("/encrypt")
    @SendTo("/topic/encrypted")
    public CipherData encrypt(PlainData plainData) {
        try {
            // 1. 接收原始数据，AES 加密
            String plainText = plainData.getPlainText();
            byte[] aesKey = SimpleAES.generateRandomKey();
            byte[] cipherText = SimpleAES.encrypt(plainText.getBytes(), aesKey);
            // 2. RSA 加密 AES Key
            BigInteger[] publicKey = SimpleRSA.readPublicKey();
            byte[] cipherKey = SimpleRSA.encrypt(aesKey, publicKey[0], publicKey[1]);
            // 3. 合并两个密文，生成数字签名
            byte[] merge = new byte[cipherText.length + cipherKey.length];
            System.arraycopy(cipherText, 0, merge, 0, cipherText.length);
            System.arraycopy(cipherKey, 0, merge, cipherText.length, cipherKey.length);
            byte[] signature = SimpleSHA.sha256(merge);
            BigInteger[] privateKey = SimpleRSA.readPrivateKey();
            byte[] cipherSignature = SimpleRSA.encrypt(signature, privateKey[0], privateKey[1]);
            // 合并数据
            return new CipherData(
                    SimpleBase64.byteToBase64(cipherText),
                    SimpleBase64.byteToBase64(cipherKey),
                    SimpleBase64.byteToBase64(cipherSignature)
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new CipherData();
    }

    @MessageMapping("/decrypt")
    @SendTo("/topic/decrypted")
    public PlainData decrypt(CipherData cipherData) {
        try {
            // 1. 接收并拆解密文数据包
            byte[] cipherText = SimpleBase64.base64ToByte(cipherData.getCipherText());
            byte[] cipherKey = SimpleBase64.base64ToByte(cipherData.getCipherKey());
            byte[] cipherSignature = SimpleBase64.base64ToByte(cipherData.getCipherSignature());

            System.out.println(Arrays.toString(cipherText));
            System.out.println(Arrays.toString(cipherKey));

            // 2. 验证签名完整性
            byte[] merge = new byte[cipherText.length + cipherKey.length];
            System.arraycopy(cipherText, 0, merge, 0, cipherText.length);
            System.arraycopy(cipherKey, 0, merge, cipherText.length, cipherKey.length);
            BigInteger[] publicKey = SimpleRSA.readPublicKey();
            byte[] signature = SimpleRSA.decrypt(cipherSignature, publicKey[0], publicKey[1]);
            if (!Arrays.equals(signature, SimpleSHA.sha256(merge))){
                throw new Exception("签名校验失败");
            }
            // 3. 解密 AES 密钥
            BigInteger[] privateKey = SimpleRSA.readPrivateKey();
            byte[] plainKey = SimpleRSA.decrypt(cipherKey, privateKey[0], privateKey[1]);
            System.out.println(Arrays.toString(plainKey));
            // 4. 解密并还原源数据
            byte[] decryptedText = SimpleAES.decrypt(cipherText, plainKey);
            System.out.println("Decrypted text: " + Arrays.toString(decryptedText));
            System.out.println("Decrypted text (as string): " + new String(decryptedText).trim());
            return new PlainData(new String(decryptedText).trim());
        } catch (Exception e) {
            e.printStackTrace();
            return new PlainData(e.getMessage());
        }
    }
}
