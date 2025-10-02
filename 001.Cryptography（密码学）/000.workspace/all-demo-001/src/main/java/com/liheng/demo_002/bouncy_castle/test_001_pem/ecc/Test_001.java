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
 * 数据加密：
 * 
 * 密钥算法：ecc
 * 
 * 密钥格式：pem
 *  		//数据加密，但是js那边不支持这种pem格式密钥对(支持pem比较麻烦)，所以这里使用pgp格式
 *  		//(示例可以成功，但实际不使用这种方式)
 * 
 * 
 *
 */
public class Test_001 {

    private static String privateKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCANAbmGWjc8TsxYhnCeGO80pD+rnz6kg9EQH1VmM2AUuA==";
    private static String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExjUb1+aTNZRCEqZcDCw8wbwgKCOyXUaHk0ORGEhQCjKil1HdYPs4KzwIvDwpDffuXd10c668JOXi/XkXcr4vEQ==";

    static {
        // 添加 Bouncy Castle 提供者
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 私钥加载函数
     */
    private static PrivateKey loadPrivateKey(String privateKeyPEM) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");  // 使用 Bouncy Castle
        return keyFactory.generatePrivate(keySpec);
    }

    /***
     * 公钥加载函数
     */
    private static PublicKey loadPublicKey(String publicKeyPEM) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");  // 使用 Bouncy Castle
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 使用公钥加密函数
     */
    private static String encryptWithPublicKey(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");  // 使用 ECIES 加密方案
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

     /**
      * 使用私钥解密函数
      **/
     private static String decryptWithPrivateKey(String encryptedData, PrivateKey privateKey) throws Exception {
         Cipher cipher = Cipher.getInstance("ECIES", "BC");  // 使用 ECIES 解密方案
         cipher.init(Cipher.DECRYPT_MODE, privateKey);
         byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
         byte[] decryptedBytes = cipher.doFinal(decodedBytes);
         return new String(decryptedBytes, "UTF-8");
     }

     /***
      * （1）web加密内部请求url和请求（使用公钥）
      */
     private static String test_001() throws Exception {
         String url = "/mftcc-flowable-server/appcenter/getApprovalDetail";
         String postHead = "{a:b,c:D}";

         // 使用公钥加密 URL 和 请求头
         String encryptedURL = encryptWithPublicKey(url, loadPublicKey(publicKey));
         String encryptedPostHead = encryptWithPublicKey(postHead, loadPublicKey(publicKey));

         // 输出加密结果
         System.out.println("Encrypted URL: " + encryptedURL);
         System.out.println("Encrypted Post Head: " + encryptedPostHead);

         return encryptedURL + " || " + encryptedPostHead;  // 拼接加密数据返回
     }

    /***
     * （2）网关服务器解密请求的数据
     */
    private static void test_002(String encryptedData) throws Exception {
        // 加密数据格式：URL || PostHead
        String[] parts = encryptedData.split(" \\|\\| ");
        String encryptedURL = parts[0];
        String encryptedPostHead = parts[1];

        // 使用私钥解密 URL 和 请求头
        String decryptedURL = decryptWithPrivateKey(encryptedURL, loadPrivateKey(privateKey));
        String decryptedPostHead = decryptWithPrivateKey(encryptedPostHead, loadPrivateKey(privateKey));

        // 输出解密结果
        System.out.println("Decrypted URL: " + decryptedURL);
        System.out.println("Decrypted Post Head: " + decryptedPostHead);
    }

    public static void main(String[] args) {
        try {
            // 生成加密后的数据
            String encryptedData = test_001();
            System.out.println("——————————————————————————————————");
            // 解密请求的数据
            test_002(encryptedData);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
