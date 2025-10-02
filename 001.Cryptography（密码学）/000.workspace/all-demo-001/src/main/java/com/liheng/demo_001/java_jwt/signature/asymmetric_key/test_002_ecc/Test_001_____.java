package com.liheng.demo_001.java_jwt.signature.asymmetric_key.test_002_ecc;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
/**
 * 先生成一对密钥，使用 ECC 算法
 * 
 * ECC生成的密钥对更短。
 *
 */
public class Test_001_____ {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 生成ECC密钥对
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256); // 设置密钥大小

        KeyPair pair = keyPairGen.generateKeyPair();
        
        // 获取私钥
        PrivateKey privateKey = pair.getPrivate();
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getEncoder().encodeToString(privateKey.getEncoded())
                + "\n-----END PRIVATE KEY-----";
        System.out.println("Private Key in PEM format:");
        System.out.println(privateKeyPEM);

        // 获取公钥
        PublicKey publicKey = pair.getPublic();
        String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getEncoder().encodeToString(publicKey.getEncoded())
                + "\n-----END PUBLIC KEY-----";
        System.out.println("Public Key in PEM format:");
        System.out.println(publicKeyPEM);
        
    }
}
