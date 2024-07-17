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
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;

/**
 * 这是预留的加密 Web API 接口类
 * 和 MessageController 里面的加密方法内容一样
 */
@RestController
@RequestMapping("/encrypt-api")
public class EncryptController {

    @PostMapping("/encrypt")
    public CipherData encrypted(@RequestBody PlainData plainData) {
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
}
