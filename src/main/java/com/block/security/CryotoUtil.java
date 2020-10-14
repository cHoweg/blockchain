package com.block.security;

import org.apache.commons.codec.binary.Hex;
import org.eclipse.jetty.util.security.Credential;

import java.security.MessageDigest;
import java.util.UUID;

/**
 * @PROJECT_NAME: blockchain
 * @DESCRIPTION: 加密工具类
 * @USER: eugenechow
 * @DATE: 2020/9/17 9:06 下午
 */
public class CryotoUtil {
    private CryotoUtil() {
    }

    public static String SHA256(String str) {
        MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes("UTF-8"));
            encodeStr = Hex.encodeHexString(messageDigest.digest());
        } catch (Exception e) {
            System.out.println(
                    "getSHA256 is error" + e.getMessage()
            );
        }
        return encodeStr;
    }

    public static String MD5(String str) {
        String resultStr = Credential.MD5.digest(str);
        return resultStr.substring(4, resultStr.length());
    }

    public static String UUID(){
        return UUID.randomUUID().toString();
    }
}
