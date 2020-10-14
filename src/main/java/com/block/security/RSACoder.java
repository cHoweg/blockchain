/*
package com.block.security;

import com.sun.org.slf4j.internal.Logger;
import com.sun.org.slf4j.internal.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.com.block.security.*;
import java.com.block.security.interfaces.RSAPrivateKey;
import java.com.block.security.interfaces.RSAPublicKey;
import java.com.block.security.spec.InvalidKeySpecException;
import java.com.block.security.spec.PKCS8EncodedKeySpec;
import java.com.block.security.spec.X509EncodedKeySpec;
import java.util.*;

*/
/**
 * RSA算法加密/解密工具类
 *//*

public class RSACoder {
    private static final Logger LOGGER = LoggerFactory.getLogger(RSACoder.class);
    */
/** 算法名称 *//*

    private static final String ALGORITHM =  "RSA";
    */
/** 默认密钥大小 *//*

    private static final int KEY_SIZE = 1024;
    */
/** 用来指定保存密钥对的文件名和存储的名称 *//*

    private static final String PUBLIC_KEY_NAME = "publicKey";
    private static final String PRIVATE_KEY_NAME = "privateKey";
    private static final String PUBLIC_FILENAME = "publicKey.properties";
    private static final String PRIVATE_FILENAME = "privateKey.properties";
    */
/** 密钥对生成器 *//*

    public static KeyPairGenerator keyPairGenerator = null;

    public static KeyFactory keyFactory = null;
    */
/** 缓存的密钥对 *//*

    public static KeyPair keyPair = null;
    */
/** Base64 编码/解码器 JDK1.8 *//*

    public static Base64.Decoder decoder = Base64.getDecoder();
    public static Base64.Encoder encoder = Base64.getEncoder();
    */
/** 初始化密钥工厂 *//*

    static{
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyFactory = KeyFactory.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error(e.getMessage(),e);
        }
    }
    */
/** 私有构造器 *//*

    private RSACoder(){}

    */
/**
     * 生成密钥对
     * 将密钥分别用Base64编码保存到#publicKey.properties#和#privateKey.properties#文件中
     * 保存的默认名称分别为publicKey和privateKey
     *//*

    public static synchronized Map<String, Object> generateKeyPair(){
        try {
            keyPairGenerator.initialize(KEY_SIZE,new SecureRandom(UUID.randomUUID().toString().replaceAll("-","").getBytes()));
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (InvalidParameterException e){
            LOGGER.error("KeyPairGenerator does not support a key length of " + KEY_SIZE + ".",e);
        } catch (NullPointerException e){
            LOGGER.error("RSACoder#key_pair_gen is null,can not generate KeyPairGenerator instance.",e);
        }
        RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
        String publicKeyString = encoder.encodeToString(rsaPublicKey.getEncoded());
        String privateKeyString = encoder.encodeToString(rsaPrivateKey.getEncoded());
        storeKey(publicKeyString,PUBLIC_KEY_NAME,PUBLIC_FILENAME);
        storeKey(privateKeyString,PRIVATE_KEY_NAME,PRIVATE_FILENAME);
        Map<String, Object> keyPair = new HashMap<>();
        keyPair.put("public", privateKeyString);
        keyPair.put("private", privateKeyString);
        return keyPair;
    }

    */
/**
     * 将指定的密钥字符串保存到文件中,如果找不到文件，就创建
     * @param keyString 密钥的Base64编码字符串（值）
     * @param keyName  保存在文件中的名称（键）
     * @param fileName 目标文件名
     *//*

    public static void storeKey(String keyString,String keyName,String fileName){
        Properties properties = new Properties();
        //存放密钥的绝对地址
        String path = null;
        try{
            path = RSACoder.class.getClassLoader().getResource(fileName).toString();
            path = path.substring(path.indexOf(":") + 1);
        }catch (NullPointerException e){
            //如果不存#fileName#就创建
            LOGGER.warn("storeKey()# " + fileName + " is not exist.Begin to create this file.");
            String classPath = RSACoder.class.getClassLoader().getResource("").toString();
            String prefix = classPath.substring(classPath.indexOf(":") + 1);
            String suffix = fileName;
            File file = new File(prefix + suffix);
            try {
                file.createNewFile();
                path = file.getAbsolutePath();
            } catch (IOException e1) {
                LOGGER.error(fileName +" create fail.",e1);
            }
        }
        try(OutputStream out = new FileOutputStream(path)){
            properties.setProperty(keyName,keyString);
            properties.store(out,"There is " + keyName);
        } catch (FileNotFoundException e) {
            LOGGER.error("ModulusAndExponent.properties is not found.",e);
        } catch (IOException e) {
            LOGGER.error("OutputStream output failed.",e);
        }
    }

    */
/**
     * 获取密钥字符串
     * @param keyName 需要获取的密钥名
     * @param fileName 密钥所在文件
     * @return Base64编码的密钥字符串
     *//*

    public static String getKeyString(String keyName,String fileName){
        if (RSACoder.class.getClassLoader().getResource(fileName) == null){
            LOGGER.warn("getKeyString()# " + fileName + " is not exist.Will run #generateKeyPair()# firstly.");
            generateKeyPair();
        }
        try(InputStream in = RSACoder.class.getClassLoader().getResource(fileName).openStream()){
            Properties properties = new Properties();
            properties.load(in);
            return properties.getProperty(keyName);
        } catch (IOException e) {
            LOGGER.error("getKeyString()#" + e.getMessage(),e);
        }
        return  null;
    }

    */
/**
     * 从文件获取RSA公钥
     * @return RSA公钥
     * @throws InvalidKeySpecException
     *//*

    public static RSAPublicKey getPublicKey(){
        try {
            byte[] keyBytes = decoder.decode(getKeyString(PUBLIC_KEY_NAME,PUBLIC_FILENAME));
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            return (RSAPublicKey)keyFactory.generatePublic(x509EncodedKeySpec);
        }catch (InvalidKeySpecException e) {
            LOGGER.error("getPublicKey()#" + e.getMessage(),e);
        }
        return null;
    }

    */
/**
     * 从文件获取RSA私钥
     * @return RSA私钥
     * @throws InvalidKeySpecException
     *//*

    public static RSAPrivateKey getPrivateKey(){
        try {
            byte[] keyBytes = decoder.decode(getKeyString(PRIVATE_KEY_NAME,PRIVATE_FILENAME));
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            return (RSAPrivateKey)keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            LOGGER.error("getPrivateKey()#" + e.getMessage(),e);
        }
        return null;
    }

    */
/**
     * RSA公钥加密
     * @param content 等待加密的数据
     * @param publicKey RSA 公钥 if null then getPublicKey()
     * @return 加密后的密文(16进制的字符串)
     *//*

    public static String encryptByPublic(byte[] content,PublicKey publicKey){
        if (publicKey == null){
            publicKey = getPublicKey();
        }
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            //该密钥能够加密的最大字节长度
            int splitLength = ((RSAPublicKey)publicKey).getModulus().bitLength() / 8 -11;
            byte[][] arrays = splitBytes(content,splitLength);
            StringBuffer stringBuffer = new StringBuffer();
            for (byte[] array : arrays){
                stringBuffer.append(bytesToHexString(cipher.doFinal(array)));
            }
            return stringBuffer.toString();
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("encrypt()#NoSuchAlgorithmException",e);
        } catch (NoSuchPaddingException e) {
            LOGGER.error("encrypt()#NoSuchPaddingException",e);
        } catch (InvalidKeyException e) {
            LOGGER.error("encrypt()#InvalidKeyException",e);
        } catch (BadPaddingException e) {
            LOGGER.error("encrypt()#BadPaddingException",e);
        } catch (IllegalBlockSizeException e) {
            LOGGER.error("encrypt()#IllegalBlockSizeException",e);
        }
        return null;
    }

    */
/**
     * RSA私钥加密
     * @param content 等待加密的数据
     * @param privateKey RSA 私钥 if null then getPrivateKey()
     * @return 加密后的密文(16进制的字符串)
     *//*

    public static String encryptByPrivate(byte[] content,PrivateKey privateKey){
        if (privateKey == null){
            privateKey = getPrivateKey();
        }
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,privateKey);
            //该密钥能够加密的最大字节长度
            int splitLength = ((RSAPrivateKey)privateKey).getModulus().bitLength() / 8 -11;
            byte[][] arrays = splitBytes(content,splitLength);
            StringBuffer stringBuffer = new StringBuffer();
            for(byte[] array : arrays){
                stringBuffer.append(bytesToHexString(cipher.doFinal(array)));
            }
            return stringBuffer.toString();
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("encrypt()#NoSuchAlgorithmException",e);
        } catch (NoSuchPaddingException e) {
            LOGGER.error("encrypt()#NoSuchPaddingException",e);
        } catch (InvalidKeyException e) {
            LOGGER.error("encrypt()#InvalidKeyException",e);
        } catch (BadPaddingException e) {
            LOGGER.error("encrypt()#BadPaddingException",e);
        } catch (IllegalBlockSizeException e) {
            LOGGER.error("encrypt()#IllegalBlockSizeException",e);
        }
        return null;
    }



    */
/**
     * RSA私钥解密
     * @param content 等待解密的数据
     * @param privateKey RSA 私钥 if null then getPrivateKey()
     * @return 解密后的明文
     *//*

    public static String decryptByPrivate(String content,PrivateKey privateKey){
        if (privateKey == null){
            privateKey = getPrivateKey();
        }
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            //该密钥能够加密的最大字节长度
            int splitLength = ((RSAPrivateKey)privateKey).getModulus().bitLength() / 8;
            byte[] contentBytes = hexStringToBytes(content);
            byte[][] arrays = splitBytes(contentBytes,splitLength);
            StringBuffer stringBuffer = new StringBuffer();
            String sTemp = null;
            for (byte[] array : arrays){
                stringBuffer.append(new String(cipher.doFinal(array)));
            }
            return stringBuffer.toString();
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("encrypt()#NoSuchAlgorithmException",e);
        } catch (NoSuchPaddingException e) {
            LOGGER.error("encrypt()#NoSuchPaddingException",e);
        } catch (InvalidKeyException e) {
            LOGGER.error("encrypt()#InvalidKeyException",e);
        } catch (BadPaddingException e) {
            LOGGER.error("encrypt()#BadPaddingException",e);
        } catch (IllegalBlockSizeException e) {
            LOGGER.error("encrypt()#IllegalBlockSizeException",e);
        }
        return null;
    }

    */
/**
     * RSA公钥解密
     * @param content 等待解密的数据
     * @param publicKey RSA 公钥 if null then getPublicKey()
     * @return 解密后的明文
     *//*

    public static String decryptByPublic(String content,PublicKey publicKey){
        if (publicKey == null){
            publicKey = getPublicKey();
        }
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,publicKey);
            //该密钥能够加密的最大字节长度
            int splitLength = ((RSAPublicKey)publicKey).getModulus().bitLength() / 8;
            byte[] contentBytes = hexStringToBytes(content);
            byte[][] arrays = splitBytes(contentBytes,splitLength);
            StringBuffer stringBuffer = new StringBuffer();
            String sTemp = null;
            for (byte[] array : arrays){
                stringBuffer.append(new String(cipher.doFinal(array)));
            }
            return stringBuffer.toString();
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("encrypt()#NoSuchAlgorithmException",e);
        } catch (NoSuchPaddingException e) {
            LOGGER.error("encrypt()#NoSuchPaddingException",e);
        } catch (InvalidKeyException e) {
            LOGGER.error("encrypt()#InvalidKeyException",e);
        } catch (BadPaddingException e) {
            LOGGER.error("encrypt()#BadPaddingException",e);
        } catch (IllegalBlockSizeException e) {
            LOGGER.error("encrypt()#IllegalBlockSizeException",e);
        }
        return null;
    }



    */
/**
     * 根据限定的每组字节长度，将字节数组分组
     * @param bytes 等待分组的字节组
     * @param splitLength 每组长度
     * @return 分组后的字节组
     *//*

    public static byte[][] splitBytes(byte[] bytes,int splitLength){
        //bytes与splitLength的余数
        int remainder = bytes.length % splitLength;
        //数据拆分后的组数，余数不为0时加1
        int quotient = remainder != 0 ? bytes.length / splitLength + 1:bytes.length / splitLength;
        byte[][] arrays = new byte[quotient][];
        byte[] array = null;
        for (int i =0;i<quotient;i++){
            //如果是最后一组（quotient-1）,同时余数不等于0，就将最后一组设置为remainder的长度
            if (i == quotient -1 && remainder != 0){
                array = new byte[remainder];
                System.arraycopy(bytes,i * splitLength,array,0,remainder);
            } else {
                array = new byte[splitLength];
                System.arraycopy(bytes,i*splitLength,array,0,splitLength);
            }
            arrays[i] = array;
        }
        return arrays;
    }

    */
/**
     * 将字节数组转换成16进制字符串
     * @param bytes 即将转换的数据
     * @return 16进制字符串
     *//*

    public static String bytesToHexString(byte[] bytes){
        StringBuffer sb = new StringBuffer(bytes.length);
        String temp = null;
        for (int i = 0;i< bytes.length;i++){
            temp = Integer.toHexString(0xFF & bytes[i]);
            if(temp.length() <2){
                sb.append(0);
            }
            sb.append(temp);
        }
        return sb.toString();
    }

    */
/**
     * 将16进制字符串转换成字节数组
     * @param hex 16进制字符串
     * @return byte[]
     *//*

    public static byte[] hexStringToBytes(String hex){
        int len = (hex.length() / 2);
        hex = hex.toUpperCase();
        byte[] result = new byte[len];
        char[] chars = hex.toCharArray();
        for (int i= 0;i<len;i++){
            int pos = i * 2;
            result[i] = (byte)(toByte(chars[pos]) << 4 | toByte(chars[pos + 1]));
        }
        return result;
    }

    */
/**
     * 将char转换为byte
     * @param c char
     * @return byte
     *//*

    public static byte toByte(char c){
        return (byte)"0123456789ABCDEF".indexOf(c);
    }


    public static void main(String[] args) {
        String s = "test";
        RSACoder.generateKeyPair();
        String c1 = RSACoder.encryptByPublic(s.getBytes(),null);
        String m1 = RSACoder.decryptByPrivate(c1,null);
        String c2 = RSACoder.encryptByPrivate(s.getBytes(),null);
        String m2 = RSACoder.decryptByPublic(c2,null);
        System.out.println(c1);
        System.out.println(m1);
        System.out.println(c2);
        System.out.println(m2);
    }
}*/

package com.block.security;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/** *//**
 * <p>
 * RSA公钥/私钥/签名工具包
 * </p>
 * <p>
 * 罗纳德·李维斯特（Ron [R]ivest）、阿迪·萨莫尔（Adi [S]hamir）和伦纳德·阿德曼（Leonard [A]dleman）
 * </p>
 * <p>
 * 字符串格式的密钥在未在特殊说明情况下都为BASE64编码格式<br/>
 * 由于非对称加密速度极其缓慢，一般文件不使用它来加密而是使用对称加密，<br/>
 * 非对称加密算法可以用来对对称加密的密钥加密，这样保证密钥的安全也就保证了数据的安全
 * </p>
 *
 * @author IceWee
 * @date 2012-4-26
 * @version 1.0
 */
public class RSACoder {

    /** *//**
     * 加密算法RSA
     */
    public static final String KEY_ALGORITHM = "RSA";

    /** *//**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    /** *//**
     * 获取公钥的key
     */
    private static final String PUBLIC_KEY = "RSAPublicKey";

    /** *//**
     * 获取私钥的key
     */
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    /** *//**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /** *//**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    /** *//**
     * <p>
     * 生成密钥对(公钥和私钥)
     * </p>
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> genKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    /** *//**
     * <p>
     * 用私钥对信息生成数字签名
     * </p>
     *
     * @param data 已加密数据
     * @param privateKey 私钥(BASE64编码)
     *
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64Utils.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64Utils.encode(signature.sign());
    }

    /** *//**
     * <p>
     * 校验数字签名
     * </p>
     *
     * @param data 已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign 数字签名
     *
     * @return
     * @throws Exception
     *
     */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64Utils.decode(sign));
    }

    /** *//**
     * <P>
     * 私钥解密
     * </p>
     *
     * @param encryptedData 已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /** *//**
     * <p>
     * 公钥解密
     * </p>
     *
     * @param encryptedData 已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /** *//**
     * <p>
     * 公钥加密
     * </p>
     *
     * @param data 源数据
     * @param publicKey 公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /** *//**
     * <p>
     * 私钥加密
     * </p>
     *
     * @param data 源数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /** *//**
     * <p>
     * 获取私钥
     * </p>
     *
     * @param keyMap 密钥对
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return Base64Utils.encode(key.getEncoded());
    }

    /** *//**
     * <p>
     * 获取公钥
     * </p>
     *
     * @param keyMap 密钥对
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return Base64Utils.encode(key.getEncoded());
    }

}