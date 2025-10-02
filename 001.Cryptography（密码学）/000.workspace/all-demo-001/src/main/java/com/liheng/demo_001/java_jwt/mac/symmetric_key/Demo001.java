package com.liheng.demo_001.java_jwt.mac.symmetric_key;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 * 
 * java_jwt��ʹ�� ���Գ���Կ�� �� mac

 * 
 */
public class Demo001 {
    private static Key key;  // ����һ����̬����Կ�����������ɺ���֤ JWT ʹ��

    private static String test_001() {
        // ����Կ����� Base64 �ַ���
        String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("Base64 Encoded Key: " + base64Key);//�磺gUwOw6KRYRjn9zTDnsF7ggeeKiffUgw2fq2bWqR3F1w=
        System.out.println("������������������������������������������������������������");
        String jwt = Jwts.builder()
                .setSubject("user123")  // �������� (ͨ�����û���ʶ)
                .setIssuer("yourapp.com") // ����ǩ����
                .setIssuedAt(new Date())  // ����ǩ��ʱ��
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // ���ù���ʱ��
                .signWith(key)  // ʹ�����ɵİ�ȫ��Կ
                .compact();  // �������յ� JWT �ַ���
        System.out.println("Generated JWT: " + jwt);
        return jwt;
    }

    private static void test_002(String jwt) {
        // ���� JWT
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)  // ���ý���ʱʹ�õ�ǩ����Կ
                .build()
                .parseClaimsJws(jwt)  // ���� JWT
                .getBody();  // ��ȡ������� Claims

        System.out.println("Parsed JWT Claims:");
        System.out.println("Subject: " + claims.getSubject());
        System.out.println("Issuer: " + claims.getIssuer());
        System.out.println("Expiration: " + claims.getExpiration());
    }

    public static void main(String[] args) {

    	//��1�� ���� ����ȫ����Կ�� ���Գ� ��Կ
        key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
 

        //��2������jwt
        String jwt = test_001();   
        System.out.println("_______________________________");

        //��3������
        test_002(jwt);  

    }
}


