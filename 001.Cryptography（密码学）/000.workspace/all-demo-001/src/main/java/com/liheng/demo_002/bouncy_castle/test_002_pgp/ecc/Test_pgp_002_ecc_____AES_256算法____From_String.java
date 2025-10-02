package com.liheng.demo_002.bouncy_castle.test_002_pgp.ecc;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
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
 * 从字符串读取 密钥
 *  
 */
public class Test_pgp_002_ecc_____AES_256算法____From_String {


	public static String publicKeyString ="-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"
			+ "\r\n"
			+ "mDMEZuwr7BYJKwYBBAHaRw8BAQdAq/cNbUZuW5c7dRlmuVH2H4PZoIvPQhuzF5DU\r\n"
			+ "z4Oz/f20ImxpaGVuZyAoZWNjKSA8MTM2ODgwMDcxNjVAMTM5LmNvbT6IkAQTFggA\r\n"
			+ "OBYhBDuX1ic7Oanzt3aRP3mUP8IgawE/BQJm7CvsAhsDBQsJCAcCBhUKCQgLAgQW\r\n"
			+ "AgMBAh4BAheAAAoJEHmUP8IgawE/ZpkBAN0xHwMyv6sM/punxpvx0B7E8y4EHeSj\r\n"
			+ "ZM4pb4DghgFgAQCdXN5wseMD8AeVzIdPDsFPeyBhPBwbYxbZZii3nMT3CLg4BGbs\r\n"
			+ "K+wSCisGAQQBl1UBBQEBB0CGOa/durKqagchUSZdiGsHe7gEmQ8+mnwnGPx39Q7W\r\n"
			+ "cQMBCAeIeAQYFggAIBYhBDuX1ic7Oanzt3aRP3mUP8IgawE/BQJm7CvsAhsMAAoJ\r\n"
			+ "EHmUP8IgawE/E0MBANwTcJFxdSSJF4rt72sceG/sYc7GmG7boT8aQwHfehmgAP9x\r\n"
			+ "QlDGbFcrnuMWmyinPxODrz+CPzlG0apj+MvSIiq7CQ==\r\n"
			+ "=4uep\r\n"
			+ "-----END PGP PUBLIC KEY BLOCK-----\r\n"
			+ "";

	public static String privateKeyString ="-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n"
			+ "\r\n"
			+ "lIYEZuwr7BYJKwYBBAHaRw8BAQdAq/cNbUZuW5c7dRlmuVH2H4PZoIvPQhuzF5DU\r\n"
			+ "z4Oz/f3+BwMC6p1zZMDCMIn/L8drK5YLcmlRpubmu/QbaV8TRjQ5mCb3aqYCsuq4\r\n"
			+ "Qre0fW/PmRiUt7TEffKuubfb6VKHhI0NEpF/JR8IBYXOtiexbnENkrQibGloZW5n\r\n"
			+ "IChlY2MpIDwxMzY4ODAwNzE2NUAxMzkuY29tPoiQBBMWCAA4FiEEO5fWJzs5qfO3\r\n"
			+ "dpE/eZQ/wiBrAT8FAmbsK+wCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQ\r\n"
			+ "eZQ/wiBrAT9mmQEA3TEfAzK/qwz+m6fGm/HQHsTzLgQd5KNkzilvgOCGAWABAJ1c\r\n"
			+ "3nCx4wPwB5XMh08OwU97IGE8HBtjFtlmKLecxPcInIsEZuwr7BIKKwYBBAGXVQEF\r\n"
			+ "AQEHQIY5r926sqpqByFRJl2Iawd7uASZDz6afCcY/Hf1DtZxAwEIB/4HAwIwZe5Y\r\n"
			+ "S9Sbq/9NKJchltvoohLMII35L0LlUux+8ma1b6tOOFewwmAY5FlvaBbjJhoizR2h\r\n"
			+ "fi2ZsvThTu2nM87boT4I8PG0R1n+PKdL7M7DiHgEGBYIACAWIQQ7l9YnOzmp87d2\r\n"
			+ "kT95lD/CIGsBPwUCZuwr7AIbDAAKCRB5lD/CIGsBPxNDAQDcE3CRcXUkiReK7e9r\r\n"
			+ "HHhv7GHOxphu26E/GkMB33oZoAD/cUJQxmxXK57jFpsopz8Tg68/gj85RtGqY/jL\r\n"
			+ "0iIquwk=\r\n"
			+ "=aTtt\r\n"
			+ "-----END PGP PRIVATE KEY BLOCK-----";

	/**
	 * 从字符串中读取 PGP 公钥
	 */
	public static PGPPublicKey readPublicKeyFromString(String publicKeyString) throws IOException, PGPException {
	    try (InputStream keyIn = new BufferedInputStream(new ByteArrayInputStream(publicKeyString.getBytes(StandardCharsets.UTF_8)))) {
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


 
	/**
	 * 从字符串中读取 PGP 私钥
	 */
	public static PGPPrivateKey readPrivateKeyFromString(String privateKeyString, char[] passphrase) throws IOException, PGPException {
	    try (InputStream keyIn = new BufferedInputStream(new ByteArrayInputStream(privateKeyString.getBytes(StandardCharsets.UTF_8)))) {
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
        
        // 创建 PGP 加密数据生成器，使用 AES_256 对称加密算法
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256) //PGPEncryptedData.AES_128，都可以，解密时自动 匹配
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
            PGPPublicKey publicKey = readPublicKeyFromString(publicKeyString);
            if (publicKey.getAlgorithm() != PGPPublicKey.ECDH) { //检测公钥的类型
                throw new IllegalArgumentException("The provided public key is not suitable for encryption.");
            }        
            
            // （2） 加密数据
            String originalData = "{\"taskId\":\"7b83bea3-758b-11ef-b1a6-005056a7f4c9\",\"taskType\":0,\"bizMark\":\"lease_approve_flow\"}";
            System.out.println("原始数据: " + originalData);
            System.out.println("原始数据字节数: " + originalData.getBytes(StandardCharsets.UTF_8).length);
            byte[] encryptedData = encryptData(originalData.getBytes(), publicKey);

            System.out.println("——————————————————————————————————————————————————————————————————————");
            String base64String = Base64.getEncoder().encodeToString(encryptedData);
            System.out.println("Base64 编码后的字符串: " + base64String);

            System.out.println("——————————————————————————————————————————————————————————————————————");
            

            // （3） 从文件中读取私钥
           
            PGPPrivateKey privateKey = readPrivateKeyFromString(privateKeyString, "123456".toCharArray());
            if (privateKey.getPublicKeyPacket().getAlgorithm() != PGPPublicKey.ECDH) {
                throw new IllegalArgumentException("The provided private key is not suitable for decryption.");
            }

            
            // （4） 解密数据            
            byte[] decryptedData = decryptData(encryptedData, privateKey);
            System.out.println("解密后的数据: " + new String(decryptedData));
            System.out.println("解密后的数据字节数: " + new String(decryptedData).getBytes(StandardCharsets.UTF_8).length);
            

        } catch (Exception e) {
            System.err.println("发生错误: ");
            e.printStackTrace();
        }
    }
}
