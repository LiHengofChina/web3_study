package com.liheng;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class KeyGeneratorExample_Base64 {
    public static void main(String[] args) throws Exception {
        // ����RSA��Կ��
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair pair = keyPairGen.generateKeyPair();

        // ��ȡ˽Կ
        PrivateKey privateKey = pair.getPrivate();
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getEncoder().encodeToString(privateKey.getEncoded())
                + "\n-----END PRIVATE KEY-----";
        System.out.println("Private Key in PEM format:");
        System.out.println(privateKeyPEM);

        // ��ȡ��Կ
        PublicKey publicKey = pair.getPublic();
        String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getEncoder().encodeToString(publicKey.getEncoded())
                + "\n-----END PUBLIC KEY-----";
        System.out.println("Public Key in PEM format:");
        System.out.println(publicKeyPEM);
    }
}
