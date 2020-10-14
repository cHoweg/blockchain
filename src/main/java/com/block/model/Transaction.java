package com.block.model;

import com.alibaba.fastjson.JSON;
import com.block.security.CryotoUtil;
import com.block.security.RSACoder;

/**
 * @PROJECT_NAME: blockchain
 * @DESCRIPTION:
 * @USER: eugenechow
 * @DATE: 2020/9/17 8:12 下午
 */
public class Transaction {
    /**
     * 交易唯一标识
     */
    private String id;

    /**
     * 交易输入
     */
    private TransactionInput txIn;

    /**
     * 交易输出
     */
    private TransactionOutput txOut;

    public Transaction() {
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public TransactionInput getTxIn() {
        return txIn;
    }

    public void setTxIn(TransactionInput txIn) {
        this.txIn = txIn;
    }

    public TransactionOutput getTxOut() {
        return txOut;
    }

    public void setTxOut(TransactionOutput txOut) {
        this.txOut = txOut;
    }

    public Transaction(String id, TransactionInput txIn, TransactionOutput txOut) {
        this.id = id;
        this.txIn = txIn;
        this.txOut = txOut;
    }

    /**
     * 是否系统生成区块的奖励交易
     *
     * @return
     */
    public boolean coinBaseTx() {
        return txIn.getTxId().equals("0") && getTxIn().getValue() == -1;
    }

    /**
     * 生成用于交易签名的交易记录副本
     *
     * @return
     */
    private Transaction cloneTx() {
        TransactionInput transactionInput = new TransactionInput(txIn.getTxId(), txIn.getValue(), null, null);
        TransactionOutput transactionOutput = new TransactionOutput(txOut.getValue(), txOut.getPublicKeyHash());
        return new Transaction(id, transactionInput, transactionOutput);
    }

    /**
     * 生成交易的hash
     * @return
     */
    private String hash() {
        return CryotoUtil.SHA256(JSON.toJSONString(this));
    }

    /**
     * 用私钥生成交易签名
     */
    public void sign(String privateKey, Transaction prevTx) {
        if (coinBaseTx()) {
            return;
        }

        if (!prevTx.getId().equals(txIn.getTxId())) {
            System.err.println("交易签名失败: 当前交易输入引用的前一笔交易与传入的前一笔交易不匹配");
        }

        Transaction txClone = cloneTx();
        txClone.getTxIn().setPublicKey(prevTx.getTxOut().getPublicKeyHash());
        String sign = "";
        try{
            sign = RSACoder.sign(txClone.hash().getBytes(),privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        txIn.setSignature(sign);
    }
}
