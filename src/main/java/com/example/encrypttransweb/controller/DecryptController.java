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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.util.Arrays;


/**
 * 这是预留的解密 Web API 接口类
 * 和 MessageController 里面的解密方法内容一样
 */
@RestController
@RequestMapping("/decrypt-api")
public class DecryptController {
    @PostMapping("/decrypt")
    public PlainData decrypted(@RequestBody CipherData cipherData) {
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
