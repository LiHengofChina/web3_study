package com.liheng.demo_001.java_jwt.mac.symmetric_key;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 *  java_jwt��ʹ�� ���Գ���Կ�� �� mac
 * ʹ�� GZIP ѹ�� �������� json token
 *
 */
public class Demo003 {

	public static String compressString(String data) throws IOException {
	    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
	    GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream);
	    gzipOutputStream.write(data.getBytes("UTF-8"));
	    gzipOutputStream.close();
	    return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
	}

	public static String decompressString(String compressedData) throws IOException {
	    byte[] compressedBytes = Base64.getDecoder().decode(compressedData);
	    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(compressedBytes);
	    GZIPInputStream gzipInputStream = new GZIPInputStream(byteArrayInputStream);
	    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
	    byte[] buffer = new byte[1024];
	    int len;
	    while ((len = gzipInputStream.read(buffer)) != -1) {
	        byteArrayOutputStream.write(buffer, 0, len);
	    }
	    return byteArrayOutputStream.toString("UTF-8");
	}
	
	private static Key key;  // ����һ����̬����Կ�����������ɺ���֤ JWT ʹ��

    private static String test_001() throws IOException {

        
    	String source = "/workstation/approval/my-approvals/pending/project-initiation-approval/7b83bea3-758b-11ef-b1a6-005056a7f4c9/c7bed00867474858808b051215d94255/lease_approve_flow/xuebeibei/primary_supplement_data/%E7%AB%8B%E9%A1%B9%E5%AE%A1%E6%89%B9";

        System.out.println("ԭ�ַ�����"+ source);
        
        String compressedUrl = compressString(source);
        System.out.println("ѹ����ģ�"+ compressedUrl);

        
        String jwt3 = Jwts.builder()
        	    .setSubject(compressedUrl)
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

        String originalUrl = decompressString(claims.getSubject());
        System.out.println("��ѹ��" + originalUrl);
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


