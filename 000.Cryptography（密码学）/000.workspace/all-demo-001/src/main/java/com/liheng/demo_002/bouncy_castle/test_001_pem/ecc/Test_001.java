package com.liheng.demo_002.bouncy_castle.test_001_pem.ecc;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * ���ݼ��ܣ�
 * 
 * ��Կ�㷨��ecc
 * 
 * ��Կ��ʽ��pem
 *  		//���ݼ��ܣ�����js�Ǳ߲�֧������pem��ʽ��Կ��(֧��pem�Ƚ��鷳)����������ʹ��pgp��ʽ
 *  		//(ʾ�����Գɹ�����ʵ�ʲ�ʹ�����ַ�ʽ)
 * 
 * 
 *
 */
public class Test_001 {

    private static String privateKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCANAbmGWjc8TsxYhnCeGO80pD+rnz6kg9EQH1VmM2AUuA==";
    private static String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExjUb1+aTNZRCEqZcDCw8wbwgKCOyXUaHk0ORGEhQCjKil1HdYPs4KzwIvDwpDffuXd10c668JOXi/XkXcr4vEQ==";

    static {
        // ��� Bouncy Castle �ṩ��
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * ˽Կ���غ���
     */
    private static PrivateKey loadPrivateKey(String privateKeyPEM) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");  // ʹ�� Bouncy Castle
        return keyFactory.generatePrivate(keySpec);
    }

    /***
     * ��Կ���غ���
     */
    private static PublicKey loadPublicKey(String publicKeyPEM) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");  // ʹ�� Bouncy Castle
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * ʹ�ù�Կ���ܺ���
     */
    private static String encryptWithPublicKey(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");  // ʹ�� ECIES ���ܷ���
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

     /**
      * ʹ��˽Կ���ܺ���
      **/
     private static String decryptWithPrivateKey(String encryptedData, PrivateKey privateKey) throws Exception {
         Cipher cipher = Cipher.getInstance("ECIES", "BC");  // ʹ�� ECIES ���ܷ���
         cipher.init(Cipher.DECRYPT_MODE, privateKey);
         byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
         byte[] decryptedBytes = cipher.doFinal(decodedBytes);
         return new String(decryptedBytes, "UTF-8");
     }

     /***
      * ��1��web�����ڲ�����url������ʹ�ù�Կ��
      */
     private static String test_001() throws Exception {
         String url = "/mftcc-flowable-server/appcenter/getApprovalDetail";
         String postHead = "{a:b,c:D}";

         // ʹ�ù�Կ���� URL �� ����ͷ
         String encryptedURL = encryptWithPublicKey(url, loadPublicKey(publicKey));
         String encryptedPostHead = encryptWithPublicKey(postHead, loadPublicKey(publicKey));

         // ������ܽ��
         System.out.println("Encrypted URL: " + encryptedURL);
         System.out.println("Encrypted Post Head: " + encryptedPostHead);

         return encryptedURL + " || " + encryptedPostHead;  // ƴ�Ӽ������ݷ���
     }

    /***
     * ��2�����ط������������������
     */
    private static void test_002(String encryptedData) throws Exception {
        // �������ݸ�ʽ��URL || PostHead
        String[] parts = encryptedData.split(" \\|\\| ");
        String encryptedURL = parts[0];
        String encryptedPostHead = parts[1];

        // ʹ��˽Կ���� URL �� ����ͷ
        String decryptedURL = decryptWithPrivateKey(encryptedURL, loadPrivateKey(privateKey));
        String decryptedPostHead = decryptWithPrivateKey(encryptedPostHead, loadPrivateKey(privateKey));

        // ������ܽ��
        System.out.println("Decrypted URL: " + decryptedURL);
        System.out.println("Decrypted Post Head: " + decryptedPostHead);
    }

    public static void main(String[] args) {
        try {
            // ���ɼ��ܺ������
            String encryptedData = test_001();
            System.out.println("��������������������������������������������������������������������");
            // �������������
            test_002(encryptedData);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
