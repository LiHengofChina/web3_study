package com.liheng.demo_001.java_jwt.signature.asymmetric_key.test_001_rsa;



import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


 
/**
 *  ʹ�� ���ǶԳ���Կ��  �� "ǩ��"��
 * 	
 *  �㷨 RSA
 *
 */
public class Demo001 {

    private static PrivateKey privateKey;  // ˽Կ������ǩ��
    private static PublicKey publicKey;    // ��Կ��������֤

    private static String test_001() {
        // ���� JWT ��ʹ��˽Կǩ��
        String jwt = Jwts.builder()
                .setSubject("user123")  // �������� (ͨ�����û���ʶ)
                .setIssuer("yourapp.com") // ����ǩ����
                .setIssuedAt(new Date())  // ����ǩ��ʱ��
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // ���ù���ʱ��
                .signWith(privateKey, SignatureAlgorithm.RS256)  // ʹ�����ɵ� RSA ˽Կ����ǩ��
                .compact();  // �������յ� JWT �ַ���
        System.out.println("Generated JWT: " + jwt);
        return jwt;
    }

    private static void test_002(String jwt) {
        // ���� JWT ��ʹ�ù�Կ��֤
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)  // ���ý���ʱʹ�õ�ǩ����Կ
                .build()
                .parseClaimsJws(jwt)  // ���� JWT
                .getBody();  // ��ȡ������� Claims

        System.out.println("Parsed JWT Claims:");
        System.out.println("Subject: " + claims.getSubject());
        System.out.println("Issuer: " + claims.getIssuer());
        System.out.println("Expiration: " + claims.getExpiration());
    }

    public static void main(String[] args) {
        try {

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);  // 2048λ��Կ

            //��1������ RSA ��Կ��
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            // ���� JWT
            String jwt = test_001();
            System.out.println("_______________________________");

            // ���� JWT
            test_002(jwt);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

