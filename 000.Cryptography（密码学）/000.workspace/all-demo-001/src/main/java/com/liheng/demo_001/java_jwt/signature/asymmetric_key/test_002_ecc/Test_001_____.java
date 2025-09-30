package com.liheng.demo_001.java_jwt.signature.asymmetric_key.test_002_ecc;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
/**
 * ������һ����Կ��ʹ�� ECC �㷨
 * 
 * ECC���ɵ���Կ�Ը��̡�
 *
 */
public class Test_001_____ {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // ����ECC��Կ��
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256); // ������Կ��С

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
