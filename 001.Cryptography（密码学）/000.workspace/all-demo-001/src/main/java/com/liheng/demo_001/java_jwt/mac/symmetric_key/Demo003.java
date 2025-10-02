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
 *  java_jwt：使用 “对称密钥” 做 mac
 * 使用 GZIP 压缩 后，再生成 json token
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
	
	private static Key key;  // 声明一个静态的密钥变量，供生成和验证 JWT 使用

    private static String test_001() throws IOException {

        
    	String source = "/workstation/approval/my-approvals/pending/project-initiation-approval/7b83bea3-758b-11ef-b1a6-005056a7f4c9/c7bed00867474858808b051215d94255/lease_approve_flow/xuebeibei/primary_supplement_data/%E7%AB%8B%E9%A1%B9%E5%AE%A1%E6%89%B9";

        System.out.println("原字符串："+ source);
        
        String compressedUrl = compressString(source);
        System.out.println("压缩后的："+ compressedUrl);

        
        String jwt3 = Jwts.builder()
        	    .setSubject(compressedUrl)
        	    .signWith(key, SignatureAlgorithm.HS256)  // 使用 HS256 算法，影响的是生成 JWT 的签名部分的长度
        	    .compact();
        System.out.println("生成的JWT: " + jwt3);
        

        return jwt3;
    }

    private static void test_002(String jwt) throws IOException {
        // 解析 JWT
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)  // 设置解析时使用的签名密钥
                .build()
                .parseClaimsJws(jwt)  // 解析 JWT
                .getBody();  // 获取解析后的 Claims

 
        System.out.println("解析后：" + claims.getSubject());

        String originalUrl = decompressString(claims.getSubject());
        System.out.println("解压后：" + originalUrl);
    }

    public static void main(String[] args) throws IOException {


    	//（1） 生成 "对称密钥"
        key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
//        String base64Key = Base64.getEncoder().encodeToString(key.getEncoded()); // 将密钥编码成 Base64 字符串
//        System.out.println("Base64 Encoded Key: " + base64Key);

        //（2）生成jwt
        String jwt = test_001();   
        System.out.println("——————————————————————————————————————————————");


        //（3）解析
        test_002(jwt);  
        
        

    }
}


