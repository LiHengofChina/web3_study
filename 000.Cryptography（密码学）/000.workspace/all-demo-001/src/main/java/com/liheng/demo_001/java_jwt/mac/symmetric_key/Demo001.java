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
 * java_jwt：使用 “对称密钥” 做 mac

 * 
 */
public class Demo001 {
    private static Key key;  // 声明一个静态的密钥变量，供生成和验证 JWT 使用

    private static String test_001() {
        // 将密钥编码成 Base64 字符串
        String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("Base64 Encoded Key: " + base64Key);//如：gUwOw6KRYRjn9zTDnsF7ggeeKiffUgw2fq2bWqR3F1w=
        System.out.println("——————————————————————————————");
        String jwt = Jwts.builder()
                .setSubject("user123")  // 设置主体 (通常是用户标识)
                .setIssuer("yourapp.com") // 设置签发者
                .setIssuedAt(new Date())  // 设置签发时间
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 设置过期时间
                .signWith(key)  // 使用生成的安全密钥
                .compact();  // 生成最终的 JWT 字符串
        System.out.println("Generated JWT: " + jwt);
        return jwt;
    }

    private static void test_002(String jwt) {
        // 解析 JWT
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)  // 设置解析时使用的签名密钥
                .build()
                .parseClaimsJws(jwt)  // 解析 JWT
                .getBody();  // 获取解析后的 Claims

        System.out.println("Parsed JWT Claims:");
        System.out.println("Subject: " + claims.getSubject());
        System.out.println("Issuer: " + claims.getIssuer());
        System.out.println("Expiration: " + claims.getExpiration());
    }

    public static void main(String[] args) {

    	//（1） 生成 “安全的密钥” ，对称 密钥
        key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
 

        //（2）生成jwt
        String jwt = test_001();   
        System.out.println("_______________________________");

        //（3）解析
        test_002(jwt);  

    }
}


