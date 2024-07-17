package com.example.encrypttransweb.bean;

public class CipherData {

    public CipherData(){}

    public CipherData(String cipherText, String encryptKey, String signatureSHA256) {
        this.cipherText = cipherText;
        this.cipherKey = encryptKey;
        this.cipherSignature = signatureSHA256;
    }

    private String cipherText;
    private String cipherKey;
    private String cipherSignature;

    public String getCipherText() {
        return cipherText;
    }

    public void setCipherText(String cipherText) {
        this.cipherText = cipherText;
    }

    public String getCipherKey() {
        return cipherKey;
    }

    public void setCipherKey(String cipherKey) {
        this.cipherKey = cipherKey;
    }

    public String getCipherSignature() {
        return cipherSignature;
    }

    public void setCipherSignature(String cipherSignature) {
        this.cipherSignature = cipherSignature;
    }
}
