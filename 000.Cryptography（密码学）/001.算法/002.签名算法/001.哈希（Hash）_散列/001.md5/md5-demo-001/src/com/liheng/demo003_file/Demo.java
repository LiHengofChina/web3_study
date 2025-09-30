package com.liheng.demo003_file;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;

public class Demo {
	private final static String[] strHex = { "0", "1", "2", "3", "4", "5",
            "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" };
	
	/**
	 * 
	 *     ������С���ļ�
	 * 	�Ƚ�ԭʼ��һ��ʵ�ַ�����
	           ���Ƚ��ļ�һ���Զ����ڴ棬
	           Ȼ��ͨ��MessageDigest����MD5���ܣ�
	           ������ֶ�����ת��Ϊ16���Ƶ�MD5ֵ��
	 * @param path
	 * @return
	 */
    public static String getMD5One(String path) {
        StringBuffer sb = new StringBuffer();
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] b = md.digest(FileUtils.readFileToByteArray(new File(path)));//
            for (int i = 0; i < b.length; i++) {
                int d = b[i];
                if (d < 0) {
                    d += 256;
                }
                int d1 = d / 16;
                int d2 = d % 16;
                sb.append(strHex[d1] + strHex[d2]);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return sb.toString();
    }
    /**
     *	 �������뷽��һ��ͬ�ĵط���Ҫ���ڲ����������������Integer��ķ���ʵ��16���Ƶ�ת�����ȷ���һ�����һЩ��
     * @param path
     * @return
     */
    public static String getMD5Two(String path) {
        StringBuffer sb = new StringBuffer("");
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(FileUtils.readFileToByteArray(new File(path)));
            byte b[] = md.digest();
            int d;
            for (int i = 0; i < b.length; i++) {
                d = b[i];
                if (d < 0) {
                    d = b[i] & 0xff;
                    // ����һ��Ч����ͬ
                    // i += 256;
                }
                if (d < 16) {
                	sb.append("0");
                }
                sb.append(Integer.toHexString(d));
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return sb.toString();
    }
    
    
    /** 
     * 
      *                       ���� �ļ�
     * 	��������ǰ������������ȣ��ڶ����ļ���Ϣ���е㲻ͬ��
     * 	�����Ƿֶ�ν�һ���ļ����룬���ڴ����ļ����ԣ��Ƚ��Ƽ����ַ�ʽ��ռ���ڴ�Ƚ��١�
     * 	����������ͨ��BigInteger���ṩ�ķ�������16���Ƶ�ת�����뷽�������ơ�
     * @param path
     * @return
     */
    public static String getMD5Three(String path) {
        BigInteger bi = null;
        try {
            byte[] buffer = new byte[8192];
            int len = 0;
            MessageDigest md = MessageDigest.getInstance("MD5");
            File f = new File(path);
            FileInputStream fis = new FileInputStream(f);
            while ((len = fis.read(buffer)) != -1) {
                md.update(buffer, 0, len);
            }
            fis.close();
            byte[] b = md.digest();
            bi = new BigInteger(1, b);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bi.toString(16);
    }
    	
    /** 
     * Apache DigestUtils �̰߳�ȫ���������м���һ���ַ�����MD5ֵ
		������ԭ��MessageDigest����Ϊ�÷���ֻ�ܱ�����һ�Σ�
		һ�������� MessageDigest ���� �ᱻ���õ���ʼ״̬�����߳�״̬�����׳���
     *            �ṩ�˻�ȡ16����MD5ֵ�ķ�������ײ�ʵ���ϣ�Ҳ�Ƿֶ�ν�һ���ļ����룬���Ʒ�����������������Ҳ����
     * @param path
     * @return
     * @throws IOException 
     * @throws FileNotFoundException 
     */
    public static String getMD5Four(String path) throws FileNotFoundException, IOException {
    	return DigestUtils.md5Hex(new FileInputStream(path));
    } 
    
    
    
    public static void main(String[] args) throws FileNotFoundException, IOException {
		
    	
		System.out.println(getMD5One("D:\\tmp\\nio.txt")); //С�ļ�
		
		System.out.println(getMD5Two("D:\\tmp\\nio.txt"));
		
		System.out.println(getMD5Three("D:\\tmp\\nio.txt")); //���ļ�
		
		
		System.out.println(getMD5Four("D:\\tmp\\nio.txt")); //���ļ������߳�
		System.out.println(getMD5Four("D:\\tmp\\nio.txt")); //���ļ������߳�
		
		
	}
}
