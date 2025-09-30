package com.liheng.demo001;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.digest.DigestUtils;

import com.liheng.demo002.MD5;

/**
 * 系统自带的MD5计算方法
 * @author 86136
 *
 */
public class MD5Utils {
	/**
	 * 使用md5的算法进行加密
	 */
	public static String md5(String plainText) {
		byte[] secretBytes = null;
		try {
			secretBytes = MessageDigest.getInstance("md5").digest(plainText.getBytes());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("没有md5这个算法！");
		}
		String md5code = new BigInteger(1, secretBytes).toString(16);// 16进制数字
		// 如果生成数字未满32位，需要前面补0
		for (int i = 0; i < 32 - md5code.length(); i++) {
			md5code = "0" + md5code;
		}
		return md5code;
	}
 
	public static void main(String[] args) throws UnsupportedEncodingException {
		
		
		//=====================内置方法
		System.out.println(md5("a" + md5("a") + "201"));
		System.out.println(md5("1" + md5("1") + "201"));
		System.out.println(md5("李恒" + md5("李恒") + "201"));
		
		 
		//=====================第三方工具多线程下操作，中文要获取 getBytes() 传入参数，
		System.out.println(DigestUtils.md5Hex("a" + DigestUtils.md5Hex("a") + "201"));
		System.out.println(DigestUtils.md5Hex("1" + DigestUtils.md5Hex("1") + "201"));
		System.out.println(DigestUtils.md5Hex(("李恒"+ DigestUtils.md5Hex("李恒".getBytes()) + "201").getBytes()));
		
		
		
		System.out.println("___________________________");
		System.out.println(DigestUtils.md5Hex("李恒".getBytes()));// 默认系统为gbk
		System.out.println(DigestUtils.md5Hex("李恒".getBytes("gbk")));//  显示指定gbk
		
		System.out.println(DigestUtils.md5Hex("李恒".getBytes("utf-8")));// 显示指定 utf-8
		System.out.println(DigestUtils.md5Hex("李恒"));//获取内部默认的 utf-8  编码
		
		
	}

}
