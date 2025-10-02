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
	 *     适用于小型文件
	 * 	比较原始的一种实现方法，
	           首先将文件一次性读入内存，
	           然后通过MessageDigest进行MD5加密，
	           最后再手动将其转换为16进制的MD5值。
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
     *	 方法二与方法一不同的地方主要是在步骤三，这里借助了Integer类的方法实现16进制的转换，比方法一更简洁一些。
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
                    // 与上一行效果等同
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
      *                       大型 文件
     * 	方法三与前面两个方法相比，在读入文件信息上有点不同。
     * 	这里是分多次将一个文件读入，对于大型文件而言，比较推荐这种方式，占用内存比较少。
     * 	步骤三则是通过BigInteger类提供的方法进行16进制的转换，与方法二类似。
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
     * Apache DigestUtils 线程安全的类来进行计算一个字符串的MD5值
		不能用原生MessageDigest，因为该方法只能被调用一次，
		一旦调用了 MessageDigest 对象， 会被重置到初始状态，多线程状态下容易出错。
     *            提供了获取16进制MD5值的方法。其底层实现上，也是分多次将一个文件读入，类似方法三。所以性能上也不错。
     * @param path
     * @return
     * @throws IOException 
     * @throws FileNotFoundException 
     */
    public static String getMD5Four(String path) throws FileNotFoundException, IOException {
    	return DigestUtils.md5Hex(new FileInputStream(path));
    } 
    
    
    
    public static void main(String[] args) throws FileNotFoundException, IOException {
		
    	
		System.out.println(getMD5One("D:\\tmp\\nio.txt")); //小文件
		
		System.out.println(getMD5Two("D:\\tmp\\nio.txt"));
		
		System.out.println(getMD5Three("D:\\tmp\\nio.txt")); //大文件
		
		
		System.out.println(getMD5Four("D:\\tmp\\nio.txt")); //大文件，多线程
		System.out.println(getMD5Four("D:\\tmp\\nio.txt")); //大文件，多线程
		
		
	}
}
