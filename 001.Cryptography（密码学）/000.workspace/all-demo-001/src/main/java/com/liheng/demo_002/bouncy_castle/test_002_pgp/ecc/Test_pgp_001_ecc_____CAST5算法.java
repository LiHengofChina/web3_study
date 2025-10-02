package com.liheng.demo_002.bouncy_castle.test_002_pgp.ecc;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/***
 * 
 *  
 */
public class Test_pgp_001_ecc_____CAST5算法 {

    /**
     * 从文件中读取 PGP 公钥
     */
    public static PGPPublicKey readPublicKey(String publicKeyPath) throws IOException, PGPException {
        try (InputStream keyIn = new BufferedInputStream(new FileInputStream(publicKeyPath))) {
            PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
                    new JcaKeyFingerprintCalculator());

            Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
            while (rIt.hasNext()) {
                PGPPublicKeyRing kRing = rIt.next();
                Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
                while (kIt.hasNext()) {
                    PGPPublicKey k = kIt.next();
                    if (k.isEncryptionKey()) {
                        return k;
                    }
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

 
    /***
     * 从文件中读取 PGP 私钥
     */
    public static PGPPrivateKey readPrivateKey(String privateKeyPath, char[] passphrase) throws IOException, PGPException {
        try (InputStream keyIn = new BufferedInputStream(new FileInputStream(privateKeyPath))) {
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
                    new JcaKeyFingerprintCalculator());

            Iterator<PGPSecretKeyRing> rIt = pgpSec.getKeyRings();
            while (rIt.hasNext()) {
                PGPSecretKeyRing kRing = rIt.next();
                Iterator<PGPSecretKey> kIt = kRing.getSecretKeys();
                while (kIt.hasNext()) {
                    PGPSecretKey k = kIt.next();
                    // 确保选择的是用于加密和解密的 cv25519 密钥
                    if (k.getPublicKey().getAlgorithm() == PGPPublicKey.ECDH) { //cv25519
                        return k.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                                .setProvider("BC").build(passphrase));
                    }
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }



    /**
     * 使用公钥加密数据
     */
    public static byte[] encryptData(byte[] data, PGPPublicKey publicKey) throws IOException, PGPException {
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        
        // 创建 PGP 加密数据生成器，使用 CAST5 对称加密算法
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));
        
        // 为加密生成器添加公钥加密方法
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

        // 将数据进行加密并写入输出流
        OutputStream cOut = encGen.open(encOut, new byte[1 << 16]);
        cOut.write(data);
        cOut.close();

        return encOut.toByteArray();
    }

    /**
     * 使用私钥解密数据
     */
    public static byte[] decryptData(byte[] encryptedData, PGPPrivateKey privateKey) throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(encryptedData);
        InputStream decoderStream = PGPUtil.getDecoderStream(in);
        
        // 使用 JcaKeyFingerprintCalculator 作为第二个参数
        PGPObjectFactory pgpFactory = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
        Object pgpObj = pgpFactory.nextObject();

        PGPEncryptedDataList encDataList;
        if (pgpObj instanceof PGPEncryptedDataList) {
            encDataList = (PGPEncryptedDataList) pgpObj;
        } else {
            encDataList = (PGPEncryptedDataList) pgpFactory.nextObject();
        }

        PGPPrivateKey sessionKey = privateKey;
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encDataList.get(0);
        InputStream decIn = encData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider("BC").build(sessionKey));

        ByteArrayOutputStream decOut = new ByteArrayOutputStream();
        int ch;
        while ((ch = decIn.read()) != -1) {
            decOut.write(ch);
        }
        decIn.close();
        return decOut.toByteArray();
    }

    public static void main(String[] args) {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // （1） 从文件中读取公钥
            PGPPublicKey publicKey = readPublicKey("pgp/ecc/publicKey.asc");
            if (publicKey.getAlgorithm() != PGPPublicKey.ECDH) { //检测公钥的类型
                throw new IllegalArgumentException("The provided public key is not suitable for encryption.");
            }        
            
            // （2） 加密数据
            String originalData = "{a:b, c:d ,中文}";
            System.out.println("原始数据: " + originalData);
            byte[] encryptedData = encryptData(originalData.getBytes(), publicKey);

           
            System.out.println("——————————————————————————————————————————————————————————————————————");
            

            // （3） 从文件中读取私钥
           
            PGPPrivateKey privateKey = readPrivateKey("pgp/ecc/privateKey.asc", "123456".toCharArray());
            if (privateKey.getPublicKeyPacket().getAlgorithm() != PGPPublicKey.ECDH) {
                throw new IllegalArgumentException("The provided private key is not suitable for decryption.");
            }

            
            // （4） 解密数据            
            byte[] decryptedData = decryptData(encryptedData, privateKey);
            System.out.println("解密后的数据: " + new String(decryptedData));

        } catch (Exception e) {
            System.err.println("发生错误: ");
            e.printStackTrace();
        }
    }
}
