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

    // 生成 PGP 密钥对的方法
    public static PGPKeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);  // 生成 2048 位 RSA 密钥
        KeyPair keyPair = keyGen.generateKeyPair();

        // 使用 SHA256 和 RSA 算法生成 PGP 密钥对
        return new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());
    }

    /**
       导出公钥到 Armored (ASCII) 格式
     */ 
    public static void exportPublicKey(PGPPublicKey publicKey, OutputStream out) throws IOException {
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(out)) {
            publicKey.encode(armoredOut);
        }
    }
 
    /**
     	导出私钥到 Armored (ASCII) 格式 
     **/ 
    public static void exportPrivateKey(PGPKeyPair pgpKeyPair, OutputStream out, char[] passPhrase) throws Exception {
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(out)) {

            // 使用 SHA-1 摘要计算器
            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);


            // 使用 CAST5 加密私钥
            PBESecretKeyEncryptor keyEncryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc)
                    .setProvider("BC")
                    .build(passPhrase);

            // 生成认证子包向量
            PGPSignatureSubpacketGenerator subpacketGen = new PGPSignatureSubpacketGenerator();
            PGPSignatureSubpacketVector hashedPackets = subpacketGen.generate(); // 生成认证子包

            // 创建 PGPSecretKey 对象
            PGPSecretKey secretKey = new PGPSecretKey(
                PGPSignature.DEFAULT_CERTIFICATION, // 默认认证
                pgpKeyPair,                         // PGP 密钥对
                "User ID",                          // 用户 ID
                sha1Calc,                           // 摘要计算器
                hashedPackets,                      // 已哈希的子包
                null,                               // 未哈希的子包
                new JcaPGPContentSignerBuilder(PGPPublicKey.RSA_GENERAL, HashAlgorithmTags.SHA256), // 使用 SHA256 的认证签名构造器
                keyEncryptor                        // 用于加密私钥的加密器
            );

            // 将私钥写入输出流
            secretKey.encode(armoredOut);
        }
    }

    public static void main(String[] args) {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // 生成密钥对
            PGPKeyPair pgpKeyPair = generateKeyPair();

            // 导出公钥
            try (FileOutputStream publicKeyOut = new FileOutputStream("publicKey.asc")) {
                exportPublicKey(pgpKeyPair.getPublicKey(), publicKeyOut);
            }
            System.out.println("公钥已保存为 publicKey.asc");

            // 导出私钥
            try (FileOutputStream privateKeyOut = new FileOutputStream("privateKey.asc")) {
                exportPrivateKey(pgpKeyPair, privateKeyOut, "yourPassphrase".toCharArray());
            }
            System.out.println("私钥已保存为 privateKey.asc");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
