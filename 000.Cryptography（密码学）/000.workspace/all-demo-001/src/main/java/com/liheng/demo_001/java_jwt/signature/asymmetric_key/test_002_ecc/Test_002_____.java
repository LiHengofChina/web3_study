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
 * “业务” 开始时生成第三方地址：
 * 利用前面生成的 “非对称密钥对” 生成jwt 和 提取jwt的内容
 * 
 * JWT 的主要目的是为了保证数据的 “完整性和真实性”，即确保 JWT 的内容在传输过程中没有被篡改
 * 
 * 
 * 所以这段代码的核心流程是：
 * 生成密钥对（ECC 算法），私钥用于签名。
 * 创建 JWT，将 URL 地址放入 subject 中，并使用私钥对 JWT 进行签名。
 * 在验证过程中，使用公钥验证 JWT 的签名是否正确，而不是加密/解密 JWT 的内容。
 * 
 */
public class Test_002_____ {

    private static String privateKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCANAbmGWjc8TsxYhnCeGO80pD+rnz6kg9EQH1VmM2AUuA==";
    private static String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExjUb1+aTNZRCEqZcDCw8wbwgKCOyXUaHk0ORGEhQCjKil1HdYPs4KzwIvDwpDffuXd10c668JOXi/XkXcr4vEQ==";

    
    /**
     * 私钥加载函数
     */
    private static PrivateKey loadPrivateKey(String privateKeyPEM) throws Exception {
        // Base64 解码
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        // 转换为 PrivateKey 对象
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }
    /***
     * 公钥加载函数
     */
    private static PublicKey loadPublicKey(String publicKeyPEM) throws Exception {
        // Base64 解码
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        // 转换为 PublicKey 对象
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }
    
    
    /***
     * （1）（使用私钥）后台业务生成第三方访问的地址：
     *  使用 私钥 (privateKey) 来对 JWT 进行签名， 签名算法是 ES256（即椭圆曲线签名算法）， 通过 signWith 方法添加签名。
     *  注意：这并不是对 JWT 进行加密，而是对 JWT 的内容 “生成一个不可篡改的签名”，用于后续验证。
     */
    private static String test_001() throws InvalidKeyException, Exception {

    	String source = "/workstation/approval/my-approvals/pending/project-initiation-approval/b5d832cb-7a72-11ef-b1a6-005056a7f4c9/c7bed00867474858808b051215d94255/lease_approve_flow/yuepeng/leaseBusManange/立项审批?opNo=xuebeibei";
    	
        String jwt = Jwts.builder()
                .setSubject(source)
                .signWith(loadPrivateKey(privateKey), SignatureAlgorithm.ES256) 
                .compact();
        System.out.println("Generated JWT: " + jwt);
        return jwt;
    }

    /***
     * （2）（使用公钥）web解密收到的 "第三方地址访问地址"
		使用了公钥 (publicKey) 来验证 JWT 的签名。使用 parseClaimsJws 方法解析 JWT 时，
		框架会自动 “使用公钥验证签名的有效性”。如果签名是由相应的私钥签名生成的，
		并且 JWT 没有被篡改，验证将通过。    
     */
    private static void test_002(String jwt) throws SignatureException, ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, IllegalArgumentException, Exception {
        // 解析 JWT 并使用公钥验证
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(loadPublicKey(publicKey))
                .build()
                .parseClaimsJws(jwt) 
                .getBody(); 

        System.out.println("Subject: " + claims.getSubject());
    }
    
    public static void main(String[] args) {
        try {

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

