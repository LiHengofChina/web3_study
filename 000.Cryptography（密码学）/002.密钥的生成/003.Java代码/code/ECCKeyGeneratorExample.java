package com.liheng;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;

public class ECCKeyGeneratorExample {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // ����ECC��Կ��
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256); // ������Կ��С

        KeyPair pair = keyPairGen.generateKeyPair();

        // ��ȡ˽Կ�͹�Կ
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        // ���˽Կ�͹�Կ
        System.out.println("Private Key: " + privateKey);
        System.out.println("Public Key: " + publicKey);
    }
}
