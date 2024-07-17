package com.example.encrypttransweb;

import com.example.encrypttransweb.utils.RSAInitializer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class EncryptTransWebApplication {

    public static void main(String[] args) {
        // 初始化 RSA 公私钥，如果启动多个项目通信，切记保证公私钥一致性
        RSAInitializer.initializeKey();

        SpringApplication.run(EncryptTransWebApplication.class, args);
    }

}
