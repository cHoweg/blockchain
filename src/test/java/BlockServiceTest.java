import com.alibaba.fastjson.JSON;
import com.block.model.*;
import org.junit.Before;
import org.junit.Test;
import com.block.security.CryotoUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * @PROJECT_NAME: blockchain
 * @DESCRIPTION: 区块链测试
 * @USER: eugeneChow
 * @DATE: 2020/9/17 8:16 下午
 */
public class BlockServiceTest {
    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testBlockMine() throws Exception {
        // 创建一个空的区块链
        List<Block> blockchain = new ArrayList<>();

        // 生成创世区块
        Block block = new Block();

        // 加入创世区块到区块链里
        blockchain.add(block);
        System.out.println(JSON.toJSONString(blockchain));

        // 创建一个空的交易集合
        List<Transaction> txs = new ArrayList<>();
        Transaction tx1 = new Transaction();
        Transaction tx2 = new Transaction();
        txs.add(tx1);
        txs.add(tx2);

        // 交易发起方
        Wallet walletSender = Wallet.generateWallet();
        // 交易接收方
        Wallet walletReciptent = Wallet.generateWallet();
        TransactionInput txIn = new TransactionInput(tx2.getId(),10,null,walletSender.getPublicKey());
        TransactionOutput txOut = new TransactionOutput(10,walletReciptent.getHashPubKey());
        Transaction tx3 = new Transaction(CryotoUtil.UUID(), txIn, txOut);

        // tx2在tx3之前已经加入区块
        tx3.sign(walletSender.getPrivateKey(),tx2);
        txs.add(tx3);

        // 加入系统奖励的交易
        Transaction sysTx = new Transaction();
        txs.add(sysTx);
        // 获取当前区块链的最后一个区块
        Block latesBlock = blockchain.get(blockchain.size() - 1);

        int nonce = new Random().nextInt(10);
        String hash = "";
        while (true) {
            // Hash = SHA256(最后一个区块的hash + 交易记录信息 + 随机数)
            hash = CryotoUtil.SHA256(latesBlock.getHash() + JSON.toJSONString(txs) + nonce);
            // System.out.println("hash:" + hash);

            if (hash.startsWith("0000")) {
                System.out.println("=====计算结果正确, 计算次数为: " + nonce + " hash: " + hash);
                break;
            }
            nonce++;
            System.out.println("计算错误, hash:" + hash);
        }

        Block newBlock = new Block(latesBlock.getIndex() + 1, hash, System.currentTimeMillis(), txs, nonce, latesBlock.getPreviousHash());
        blockchain.add(newBlock);
        System.out.println("挖矿后的区块链: " + JSON.toJSONString(blockchain));
    }


}
