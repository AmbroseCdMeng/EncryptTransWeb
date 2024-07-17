package com.example.encrypttransweb.utils;

/**
 * RSA 算法初始化公私钥
 */
public class RSAInitializer {

    public static void initializeKey(){
        try {
            SimpleRSA rsa = new SimpleRSA(1024);
            rsa.initializeRSA();
            System.out.println("RSA 公私钥初始化成功");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
