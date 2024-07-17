package com.example.encrypttransweb.bean;

public class PlainData {
    private String plainText;

    public PlainData(){}

    public PlainData(String plainText){
        this.plainText = plainText;
    }

    public String getPlainText() {
        return plainText;
    }

    public void setPlainText(String plainText) {
        this.plainText = plainText;
    }
}
