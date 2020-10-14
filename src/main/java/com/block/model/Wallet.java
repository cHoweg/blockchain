package com.block.model;

import com.block.security.CryotoUtil;
import com.block.security.RSACoder;

import java.util.Map;

/**
 * @PROJECT_NAME: blockchain
 * @DESCRIPTION:钱包
 * @USER: eugenechow
 * @DATE: 2020/9/21 10:02 下午
 */
public class Wallet {
    /**
     * 公钥
     */
    private String publicKey;

    /**
     * 私钥
     */
    private String privateKey;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public Wallet() {
    }

    public Wallet(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }


    public static Wallet generateWallet(){
        Map<String,Object> initKey;
        try {
            // 本地生成公私钥对
            initKey = RSACoder.genKeyPair();
            String publicKey = RSACoder.getPublicKey(initKey);
            String privateKey = RSACoder.getPrivateKey(initKey);
            return new Wallet(publicKey,privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 获取钱包地址
     */
    public String getAddress(){
        String pubKeyHash = hashPubKey(publicKey);
        return CryotoUtil.MD5(pubKeyHash);
    }

    /**
     * 根据钱包公钥生成钱包地址
     * @param publicKey
     * @return
     */
    public static String getAddress(String publicKey){
        String pubKeyHash = hashPubKey(publicKey);
        return CryotoUtil.MD5(pubKeyHash);
    }

    /**
     * 获取钱包公钥
     * @return
     */
    public String getHashPubKey(){
        return CryotoUtil.SHA256(publicKey);
    }

    /**
     * 生成钱包公钥hash
     *
     * @param publicKey
     */
    public static String hashPubKey(String publicKey) {
        return CryotoUtil.SHA256(publicKey);
    }
}
