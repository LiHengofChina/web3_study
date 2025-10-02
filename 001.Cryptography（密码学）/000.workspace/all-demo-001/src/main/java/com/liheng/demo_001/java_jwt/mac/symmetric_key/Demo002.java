package com.liheng.demo_001.java_jwt.mac.symmetric_key;

import java.io.IOException;
import java.security.Key;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 * java_jwt：使用 “对称密钥” 做 mac
 * 对比几种hash算法生成的jwt的长度
 *
 */
public class Demo002 {

	
	private static Key key;  // 声明一个静态的密钥变量，供生成和验证 JWT 使用

    private static String test_001() throws IOException {
    	
    	
    	String source = "/workstation/approval/my-approvals/pending/project-initiation-approval/7b83bea3-758b-11ef-b1a6-005056a7f4c9/c7bed00867474858808b051215d94255/lease_approve_flow/xuebeibei/primary_supplement_data/%E7%AB%8B%E9%A1%B9%E5%AE%A1%E6%89%B9";

        System.out.println("原字符串："+ source);
        
        System.out.println("（一）：");
        String jwt1 = Jwts.builder()
                .setSubject(source) 
                .signWith(key)//根据 key 的类型自动确定签名算法。
                .compact(); 
        System.out.println("Generated JWT: " + jwt1);

        System.out.println("（二）：");
        String jwt2 = Jwts.builder()
        	    .setSubject(source)
        	    .signWith(key, SignatureAlgorithm.HS384)  // 使用 HS384 算法，影响的是生成 JWT 的签名部分的长度
        	    .compact();
        System.out.println("Generated JWT: " + jwt2);
 
        
      
        System.out.println("（三）：短");
 
        String jwt3 = Jwts.builder()
        	    .setSubject(source)
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


