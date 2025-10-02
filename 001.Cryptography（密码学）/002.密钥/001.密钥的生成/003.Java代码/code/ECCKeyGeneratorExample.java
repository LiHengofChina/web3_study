package com.liheng;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;

public class ECCKeyGeneratorExample {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 生成ECC密钥对
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256); // 设置密钥大小

        KeyPair pair = keyPairGen.generateKeyPair();

        // 获取私钥和公钥
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        // 输出私钥和公钥
        System.out.println("Private Key: " + privateKey);
        System.out.println("Public Key: " + publicKey);
    }
}
