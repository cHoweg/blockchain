package com.block.model;

/**
 * @PROJECT_NAME: blockchain
 * @DESCRIPTION:
 * @USER: eugenechow
 * @DATE: 2020/9/22 10:44 上午
 */
public class TransactionInput {
    /**
     * 前一次交易id
     */
    private String txId;

    /**
     * 交易金额
     */
    private int value;

    /**
     * 交易签名
     */
    private String signature;

    /**
     * 交易发送方的钱包公钥
     */
    private String publicKey;

    public TransactionInput() {
    }

    public TransactionInput(String txId, int value, String signature, String publicKey) {
        this.txId = txId;
        this.value = value;
        this.signature = signature;
        this.publicKey = publicKey;
    }

    public String getTxId() {
        return txId;
    }

    public void setTxId(String txId) {
        this.txId = txId;
    }

    public int getValue() {
        return value;
    }

    public void setValue(int value) {
        this.value = value;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
