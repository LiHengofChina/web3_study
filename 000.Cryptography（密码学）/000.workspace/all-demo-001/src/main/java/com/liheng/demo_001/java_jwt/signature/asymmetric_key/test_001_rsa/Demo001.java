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
 *  使用 “非对称密钥”  做 "签名"，
 * 	
 *  算法 RSA
 *
 */
public class Demo001 {

    private static PrivateKey privateKey;  // 私钥，用于签名
    private static PublicKey publicKey;    // 公钥，用于验证

    private static String test_001() {
        // 生成 JWT 并使用私钥签名
        String jwt = Jwts.builder()
                .setSubject("user123")  // 设置主体 (通常是用户标识)
                .setIssuer("yourapp.com") // 设置签发者
                .setIssuedAt(new Date())  // 设置签发时间
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 设置过期时间
                .signWith(privateKey, SignatureAlgorithm.RS256)  // 使用生成的 RSA 私钥进行签名
                .compact();  // 生成最终的 JWT 字符串
        System.out.println("Generated JWT: " + jwt);
        return jwt;
    }

    private static void test_002(String jwt) {
        // 解析 JWT 并使用公钥验证
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)  // 设置解析时使用的签名公钥
                .build()
                .parseClaimsJws(jwt)  // 解析 JWT
                .getBody();  // 获取解析后的 Claims

        System.out.println("Parsed JWT Claims:");
        System.out.println("Subject: " + claims.getSubject());
        System.out.println("Issuer: " + claims.getIssuer());
        System.out.println("Expiration: " + claims.getExpiration());
    }

    public static void main(String[] args) {
        try {

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);  // 2048位密钥

            //（1）生成 RSA 密钥对
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            // 生成 JWT
            String jwt = test_001();
            System.out.println("_______________________________");

            // 解析 JWT
            test_002(jwt);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

