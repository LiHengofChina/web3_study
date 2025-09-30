package com.liheng.demo_001.java_jwt.signature.asymmetric_key.test_002_ecc;



import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SignatureException;


 
/**
 * ��ҵ�� ��ʼʱ���ɵ�������ַ��
 * ����ǰ�����ɵ� ���ǶԳ���Կ�ԡ� ����jwt �� ��ȡjwt������
 * 
 * JWT ����ҪĿ����Ϊ�˱�֤���ݵ� �������Ժ���ʵ�ԡ�����ȷ�� JWT �������ڴ��������û�б��۸�
 * 
 * 
 * ������δ���ĺ��������ǣ�
 * ������Կ�ԣ�ECC �㷨����˽Կ����ǩ����
 * ���� JWT���� URL ��ַ���� subject �У���ʹ��˽Կ�� JWT ����ǩ����
 * ����֤�����У�ʹ�ù�Կ��֤ JWT ��ǩ���Ƿ���ȷ�������Ǽ���/���� JWT �����ݡ�
 * 
 */
public class Test_002_____ {

    private static String privateKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCANAbmGWjc8TsxYhnCeGO80pD+rnz6kg9EQH1VmM2AUuA==";
    private static String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExjUb1+aTNZRCEqZcDCw8wbwgKCOyXUaHk0ORGEhQCjKil1HdYPs4KzwIvDwpDffuXd10c668JOXi/XkXcr4vEQ==";

    
    /**
     * ˽Կ���غ���
     */
    private static PrivateKey loadPrivateKey(String privateKeyPEM) throws Exception {
        // Base64 ����
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        // ת��Ϊ PrivateKey ����
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }
    /***
     * ��Կ���غ���
     */
    private static PublicKey loadPublicKey(String publicKeyPEM) throws Exception {
        // Base64 ����
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        // ת��Ϊ PublicKey ����
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }
    
    
    /***
     * ��1����ʹ��˽Կ����̨ҵ�����ɵ��������ʵĵ�ַ��
     *  ʹ�� ˽Կ (privateKey) ���� JWT ����ǩ���� ǩ���㷨�� ES256������Բ����ǩ���㷨���� ͨ�� signWith �������ǩ����
     *  ע�⣺�Ⲣ���Ƕ� JWT ���м��ܣ����Ƕ� JWT ������ ������һ�����ɴ۸ĵ�ǩ���������ں�����֤��
     */
    private static String test_001() throws InvalidKeyException, Exception {

    	String source = "/workstation/approval/my-approvals/pending/project-initiation-approval/b5d832cb-7a72-11ef-b1a6-005056a7f4c9/c7bed00867474858808b051215d94255/lease_approve_flow/yuepeng/leaseBusManange/��������?opNo=xuebeibei";
    	
        String jwt = Jwts.builder()
                .setSubject(source)
                .signWith(loadPrivateKey(privateKey), SignatureAlgorithm.ES256) 
                .compact();
        System.out.println("Generated JWT: " + jwt);
        return jwt;
    }

    /***
     * ��2����ʹ�ù�Կ��web�����յ��� "��������ַ���ʵ�ַ"
		ʹ���˹�Կ (publicKey) ����֤ JWT ��ǩ����ʹ�� parseClaimsJws �������� JWT ʱ��
		��ܻ��Զ� ��ʹ�ù�Կ��֤ǩ������Ч�ԡ������ǩ��������Ӧ��˽Կǩ�����ɵģ�
		���� JWT û�б��۸ģ���֤��ͨ����    
     */
    private static void test_002(String jwt) throws SignatureException, ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, IllegalArgumentException, Exception {
        // ���� JWT ��ʹ�ù�Կ��֤
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(loadPublicKey(publicKey))
                .build()
                .parseClaimsJws(jwt) 
                .getBody(); 

        System.out.println("Subject: " + claims.getSubject());
    }
    
    public static void main(String[] args) {
        try {

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

