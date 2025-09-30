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
public class Test_pgp_001_ecc_____CAST5�㷨 {

    /**
     * ���ļ��ж�ȡ PGP ��Կ
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
     * ���ļ��ж�ȡ PGP ˽Կ
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
                    // ȷ��ѡ��������ڼ��ܺͽ��ܵ� cv25519 ��Կ
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
     * ʹ�ù�Կ��������
     */
    public static byte[] encryptData(byte[] data, PGPPublicKey publicKey) throws IOException, PGPException {
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        
        // ���� PGP ����������������ʹ�� CAST5 �ԳƼ����㷨
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));
        
        // Ϊ������������ӹ�Կ���ܷ���
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

        // �����ݽ��м��ܲ�д�������
        OutputStream cOut = encGen.open(encOut, new byte[1 << 16]);
        cOut.write(data);
        cOut.close();

        return encOut.toByteArray();
    }

    /**
     * ʹ��˽Կ��������
     */
    public static byte[] decryptData(byte[] encryptedData, PGPPrivateKey privateKey) throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(encryptedData);
        InputStream decoderStream = PGPUtil.getDecoderStream(in);
        
        // ʹ�� JcaKeyFingerprintCalculator ��Ϊ�ڶ�������
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

            // ��1�� ���ļ��ж�ȡ��Կ
            PGPPublicKey publicKey = readPublicKey("pgp/ecc/publicKey.asc");
            if (publicKey.getAlgorithm() != PGPPublicKey.ECDH) { //��⹫Կ������
                throw new IllegalArgumentException("The provided public key is not suitable for encryption.");
            }        
            
            // ��2�� ��������
            String originalData = "{a:b, c:d ,����}";
            System.out.println("ԭʼ����: " + originalData);
            byte[] encryptedData = encryptData(originalData.getBytes(), publicKey);

           
            System.out.println("��������������������������������������������������������������������������������������������������������������������������������������������");
            

            // ��3�� ���ļ��ж�ȡ˽Կ
           
            PGPPrivateKey privateKey = readPrivateKey("pgp/ecc/privateKey.asc", "123456".toCharArray());
            if (privateKey.getPublicKeyPacket().getAlgorithm() != PGPPublicKey.ECDH) {
                throw new IllegalArgumentException("The provided private key is not suitable for decryption.");
            }

            
            // ��4�� ��������            
            byte[] decryptedData = decryptData(encryptedData, privateKey);
            System.out.println("���ܺ������: " + new String(decryptedData));

        } catch (Exception e) {
            System.err.println("��������: ");
            e.printStackTrace();
        }
    }
}
