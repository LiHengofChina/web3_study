package com.liheng.demo001;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.digest.DigestUtils;

import com.liheng.demo002.MD5;

/**
 * ϵͳ�Դ���MD5���㷽��
 * @author 86136
 *
 */
public class MD5Utils {
	/**
	 * ʹ��md5���㷨���м���
	 */
	public static String md5(String plainText) {
		byte[] secretBytes = null;
		try {
			secretBytes = MessageDigest.getInstance("md5").digest(plainText.getBytes());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("û��md5����㷨��");
		}
		String md5code = new BigInteger(1, secretBytes).toString(16);// 16��������
		// �����������δ��32λ����Ҫǰ�油0
		for (int i = 0; i < 32 - md5code.length(); i++) {
			md5code = "0" + md5code;
		}
		return md5code;
	}
 
	public static void main(String[] args) throws UnsupportedEncodingException {
		
		
		//=====================���÷���
		System.out.println(md5("a" + md5("a") + "201"));
		System.out.println(md5("1" + md5("1") + "201"));
		System.out.println(md5("���" + md5("���") + "201"));
		
		 
		//=====================���������߶��߳��²���������Ҫ��ȡ getBytes() ���������
		System.out.println(DigestUtils.md5Hex("a" + DigestUtils.md5Hex("a") + "201"));
		System.out.println(DigestUtils.md5Hex("1" + DigestUtils.md5Hex("1") + "201"));
		System.out.println(DigestUtils.md5Hex(("���"+ DigestUtils.md5Hex("���".getBytes()) + "201").getBytes()));
		
		
		
		System.out.println("___________________________");
		System.out.println(DigestUtils.md5Hex("���".getBytes()));// Ĭ��ϵͳΪgbk
		System.out.println(DigestUtils.md5Hex("���".getBytes("gbk")));//  ��ʾָ��gbk
		
		System.out.println(DigestUtils.md5Hex("���".getBytes("utf-8")));// ��ʾָ�� utf-8
		System.out.println(DigestUtils.md5Hex("���"));//��ȡ�ڲ�Ĭ�ϵ� utf-8  ����
		
		
	}

}
