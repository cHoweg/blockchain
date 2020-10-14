package com.block.model;

/**
 * @PROJECT_NAME: blockchain
 * @DESCRIPTION:
 * @USER: eugenechow
 * @DATE: 2020/9/22 10:47 上午
 */
public class TransactionOutput {
    /**
     * 交易金额
     */
    private int value;

    /**
     * 交易接收方的钱包公钥的hash值
     */
    private String publicKeyHash;

    public TransactionOutput() {
    }

    public TransactionOutput(int value, String publicKeyHash) {
        this.value = value;
        this.publicKeyHash = publicKeyHash;
    }

    public int getValue() {
        return value;
    }

    public void setValue(int value) {
        this.value = value;
    }

    public String getPublicKeyHash() {
        return publicKeyHash;
    }

    public void setPublicKeyHash(String publicKeyHash) {
        this.publicKeyHash = publicKeyHash;
    }
}