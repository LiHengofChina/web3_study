package com.liheng.demo_002.bouncy_castle.test_002_pgp.ecc.spring_boot;


import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

@Service
public class PgpService {

	public static String PUBLIC_KEY_STRING ="-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"
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
    // 从字符串中读取 PGP 公钥
    public PGPPublicKey readPublicKeyFromString() throws IOException, PGPException {
        try (InputStream keyIn = new BufferedInputStream(new ByteArrayInputStream(PUBLIC_KEY_STRING.getBytes(StandardCharsets.UTF_8)))) {
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
    
    // 使用公钥加密数据
    public byte[] encryptData(byte[] data, PGPPublicKey publicKey) throws IOException, PGPException {
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));

        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

        OutputStream cOut = encGen.open(encOut, new byte[1 << 16]);
        cOut.write(data);
        cOut.close();

        return encOut.toByteArray();
    }
    public PgpService() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    
    
    
    
    
	public static String PRIVATE_KEY_STRING ="-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n"
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
    // 从字符串中读取 PGP 私钥
    public PGPPrivateKey readPrivateKeyFromString() throws IOException, PGPException {
        try (InputStream keyIn = new BufferedInputStream(new ByteArrayInputStream(PRIVATE_KEY_STRING.getBytes(StandardCharsets.UTF_8)))) {
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
                    new JcaKeyFingerprintCalculator());

            Iterator<PGPSecretKeyRing> rIt = pgpSec.getKeyRings();
            while (rIt.hasNext()) {
                PGPSecretKeyRing kRing = rIt.next();
                Iterator<PGPSecretKey> kIt = kRing.getSecretKeys();
                while (kIt.hasNext()) {
                    PGPSecretKey k = kIt.next();
                    if (k.getPublicKey().getAlgorithm() == PGPPublicKey.ECDH) { //cv25519
                        return k.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                                .setProvider("BC").build("123456".toCharArray()));
                    }
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }
    // 使用私钥解密数据
    public byte[] decryptData(byte[] encryptedData) throws IOException, PGPException {


        PGPPrivateKey privateKey = readPrivateKeyFromString();
        if (privateKey.getPublicKeyPacket().getAlgorithm() != PGPPublicKey.ECDH) {
            throw new IllegalArgumentException("The provided private key is not suitable for decryption.");
        }
        
        ByteArrayInputStream in = new ByteArrayInputStream(encryptedData);
        InputStream decoderStream = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpFactory = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
        Object pgpObj = pgpFactory.nextObject();

        PGPEncryptedDataList encDataList;
        if (pgpObj instanceof PGPEncryptedDataList) {
            encDataList = (PGPEncryptedDataList) pgpObj;
        } else {
            encDataList = (PGPEncryptedDataList) pgpFactory.nextObject();
        }

        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encDataList.get(0);
        InputStream decIn = encData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider("BC").build(privateKey));

        ByteArrayOutputStream decOut = new ByteArrayOutputStream();
        int ch;
        while ((ch = decIn.read()) != -1) {
            decOut.write(ch);
        }
        decIn.close();
        return decOut.toByteArray();
    }
}
