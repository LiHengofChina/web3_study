package com.liheng.demo_003;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class PGPKeyGenerator {

    // ���� PGP ��Կ�Եķ���
    public static PGPKeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);  // ���� 2048 λ RSA ��Կ
        KeyPair keyPair = keyGen.generateKeyPair();

        // ʹ�� SHA256 �� RSA �㷨���� PGP ��Կ��
        return new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());
    }

    /**
       ������Կ�� Armored (ASCII) ��ʽ
     */ 
    public static void exportPublicKey(PGPPublicKey publicKey, OutputStream out) throws IOException {
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(out)) {
            publicKey.encode(armoredOut);
        }
    }
 
    /**
     	����˽Կ�� Armored (ASCII) ��ʽ 
     **/ 
    public static void exportPrivateKey(PGPKeyPair pgpKeyPair, OutputStream out, char[] passPhrase) throws Exception {
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(out)) {

            // ʹ�� SHA-1 ժҪ������
            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);


            // ʹ�� CAST5 ����˽Կ
            PBESecretKeyEncryptor keyEncryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc)
                    .setProvider("BC")
                    .build(passPhrase);

            // ������֤�Ӱ�����
            PGPSignatureSubpacketGenerator subpacketGen = new PGPSignatureSubpacketGenerator();
            PGPSignatureSubpacketVector hashedPackets = subpacketGen.generate(); // ������֤�Ӱ�

            // ���� PGPSecretKey ����
            PGPSecretKey secretKey = new PGPSecretKey(
                PGPSignature.DEFAULT_CERTIFICATION, // Ĭ����֤
                pgpKeyPair,                         // PGP ��Կ��
                "User ID",                          // �û� ID
                sha1Calc,                           // ժҪ������
                hashedPackets,                      // �ѹ�ϣ���Ӱ�
                null,                               // δ��ϣ���Ӱ�
                new JcaPGPContentSignerBuilder(PGPPublicKey.RSA_GENERAL, HashAlgorithmTags.SHA256), // ʹ�� SHA256 ����֤ǩ��������
                keyEncryptor                        // ���ڼ���˽Կ�ļ�����
            );

            // ��˽Կд�������
            secretKey.encode(armoredOut);
        }
    }

    public static void main(String[] args) {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // ������Կ��
            PGPKeyPair pgpKeyPair = generateKeyPair();

            // ������Կ
            try (FileOutputStream publicKeyOut = new FileOutputStream("publicKey.asc")) {
                exportPublicKey(pgpKeyPair.getPublicKey(), publicKeyOut);
            }
            System.out.println("��Կ�ѱ���Ϊ publicKey.asc");

            // ����˽Կ
            try (FileOutputStream privateKeyOut = new FileOutputStream("privateKey.asc")) {
                exportPrivateKey(pgpKeyPair, privateKeyOut, "yourPassphrase".toCharArray());
            }
            System.out.println("˽Կ�ѱ���Ϊ privateKey.asc");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
