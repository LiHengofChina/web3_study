package com.liheng.demo_001.java_jwt.mac.symmetric_key;

import java.io.IOException;
import java.security.Key;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 * java_jwt��ʹ�� ���Գ���Կ�� �� mac
 * �Աȼ���hash�㷨���ɵ�jwt�ĳ���
 *
 */
public class Demo002 {

	
	private static Key key;  // ����һ����̬����Կ�����������ɺ���֤ JWT ʹ��

    private static String test_001() throws IOException {
    	
    	
    	String source = "/workstation/approval/my-approvals/pending/project-initiation-approval/7b83bea3-758b-11ef-b1a6-005056a7f4c9/c7bed00867474858808b051215d94255/lease_approve_flow/xuebeibei/primary_supplement_data/%E7%AB%8B%E9%A1%B9%E5%AE%A1%E6%89%B9";

        System.out.println("ԭ�ַ�����"+ source);
        
        System.out.println("��һ����");
        String jwt1 = Jwts.builder()
                .setSubject(source) 
                .signWith(key)//���� key �������Զ�ȷ��ǩ���㷨��
                .compact(); 
        System.out.println("Generated JWT: " + jwt1);

        System.out.println("��������");
        String jwt2 = Jwts.builder()
        	    .setSubject(source)
        	    .signWith(key, SignatureAlgorithm.HS384)  // ʹ�� HS384 �㷨��Ӱ��������� JWT ��ǩ�����ֵĳ���
        	    .compact();
        System.out.println("Generated JWT: " + jwt2);
 
        
      
        System.out.println("����������");
 
        String jwt3 = Jwts.builder()
        	    .setSubject(source)
        	    .signWith(key, SignatureAlgorithm.HS256)  // ʹ�� HS256 �㷨��Ӱ��������� JWT ��ǩ�����ֵĳ���
        	    .compact();
        System.out.println("���ɵ�JWT: " + jwt3);
        

        return jwt3;
    }

    private static void test_002(String jwt) throws IOException {
        // ���� JWT
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)  // ���ý���ʱʹ�õ�ǩ����Կ
                .build()
                .parseClaimsJws(jwt)  // ���� JWT
                .getBody();  // ��ȡ������� Claims

 
        System.out.println("������" + claims.getSubject());

    }

    public static void main(String[] args) throws IOException {


    	//��1�� ���� "�Գ���Կ"
        key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
//        String base64Key = Base64.getEncoder().encodeToString(key.getEncoded()); // ����Կ����� Base64 �ַ���
//        System.out.println("Base64 Encoded Key: " + base64Key);

        //��2������jwt
        String jwt = test_001();   
        System.out.println("��������������������������������������������������������������������������������������������");


        //��3������
        test_002(jwt);  
        
        

    }
}


