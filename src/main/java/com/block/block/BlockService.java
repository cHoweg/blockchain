package com.block.block;

import com.alibaba.fastjson.JSON;
import com.block.model.*;
import com.block.security.CryotoUtil;

import java.util.*;

/**
 * @PROJECT_NAME: blockchain
 * @DESCRIPTION:
 * @USER: eugenechow
 * @DATE: 2020/9/23 10:50 下午
 */
public class BlockService {
    /**
     * 区块链存储结构
     */
    private List<Block> blockChain = new ArrayList<Block>();

    /**
     * 当前节点钱包集合
     */
    private Map<String, Wallet> myWalletMap = new HashMap<>();

    /**
     * 其他节点钱包集合 钱包只包含公钥
     */
    private Map<String, Wallet> otherWalletMap = new HashMap<>();

    /**
     * 转账交易集合
     */
    private List<Transaction> allTransactions = new ArrayList<>();

    /**
     * 已打包转账交易
     */
    private List<Transaction> packerTransactions = new ArrayList<>();

    public BlockService() {
        // 创建始创区块
        Block genesisBlock = new Block(1, "1", System.currentTimeMillis(), new ArrayList<Transaction>(), 1, "1");
        blockChain.add(genesisBlock);
        System.out.println("生成创始区块: " + JSON.toJSONString(genesisBlock));
    }

    /**
     * 获取最新的区块, 即当前链上最后一个区块
     *
     * @return
     */
    public Block getLatestBlock() {
        return blockChain.size() > 0 ? blockChain.get(blockChain.size() - 1) : null;
    }

    public Transaction createTransaction(Wallet senderWallet, Wallet recipientWallet, int amount) {
        List<Transaction> unspentTxs = findUnspentTransactions(senderWallet.getAddress());
        Transaction prevTx = null;
        for (Transaction transaction : unspentTxs) {
            // TODO 找零
            if (transaction.getTxOut().getValue() == amount) {
                prevTx = transaction;
                break;
            }
        }
        if (prevTx == null) {
            return null;
        }
        TransactionInput txIn = new TransactionInput(prevTx.getId(), amount, null, senderWallet.getPublicKey());
        TransactionOutput txOut = new TransactionOutput(amount, recipientWallet.getHashPubKey());
        Transaction transaction = new Transaction(CryotoUtil.UUID(), txIn, txOut);
        allTransactions.add(transaction);
        return transaction;
    }

    /**
     * 挖矿
     *
     * @param toAddress
     * @return
     */
    /*public Block mine(String toAddress) {
        // 创建系统奖励的交易
        allTransactions.add(newCoinbaseTx(toAddress));
        // 去除已经打包进区块的交易
        List<Transaction> blockTxs = new ArrayList<>(allTransactions);
        blockTxs.removeAll(packerTransactions);
        verifyAllTransactions(blockTxs);

        String newBlockHash = "";
        int nonce = 0;
        long start = System.currentTimeMillis();
        System.out.println("开始挖矿");
        while (true) {
            // 计算新区块的hash值

        }

    }*/

    private List<Transaction> findUnspentTransactions(String address) {
        List<Transaction> unspentTxs = new ArrayList<>();
        Set<String> spentTxs = new HashSet<>();
        for (Transaction tx :
                allTransactions) {
            if (tx.coinBaseTx()) {
                continue;
            }
            if (address.equals(Wallet.getAddress(tx.getTxIn().getPublicKey()))) {
                spentTxs.add(tx.getTxIn().getTxId());
            }
        }

        for (Block block : blockChain) {
            List<Transaction> transactions = block.getTransactions();
            for (Transaction tx :
                    transactions) {
                if (address.equals(CryotoUtil.MD5(tx.getTxOut().getPublicKeyHash()))) {
                    if (!spentTxs.contains(tx.getId())) {
                        unspentTxs.add(tx);
                    }
                }
            }
        }
        return unspentTxs;
    }

    public Wallet createWallet() {
        Wallet wallet = Wallet.generateWallet();
        String address = wallet.getAddress();
        myWalletMap.put(address, wallet);
        return wallet;
    }

    /**
     * 获取钱包余额
     *
     * @param address
     * @return
     */
    private int getWalletBalance(String address) {
        List<Transaction> unspentTxs = findUnspentTransactions(address);
        int balance = 0;
        for (Transaction tx :
                unspentTxs) {
            balance += tx.getTxOut().getValue();
        }
        return balance;
    }

    public List<Block> getBlockChain() {
        return blockChain;
    }

    public void setBlockChain(List<Block> blockChain) {
        this.blockChain = blockChain;
    }

    public Map<String, Wallet> getMyWalletMap() {
        return myWalletMap;
    }

    public void setMyWalletMap(Map<String, Wallet> myWalletMap) {
        this.myWalletMap = myWalletMap;
    }

    public Map<String, Wallet> getOtherWalletMap() {
        return otherWalletMap;
    }

    public void setOtherWalletMap(Map<String, Wallet> otherWalletMap) {
        this.otherWalletMap = otherWalletMap;
    }

    public List<Transaction> getAllTransactions() {
        return allTransactions;
    }

    public void setAllTransactions(List<Transaction> allTransactions) {
        this.allTransactions = allTransactions;
    }

    public List<Transaction> getPackerTransactions() {
        return packerTransactions;
    }

    public void setPackerTransactions(List<Transaction> packerTransactions) {
        this.packerTransactions = packerTransactions;
    }
}
