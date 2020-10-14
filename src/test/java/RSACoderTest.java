import org.junit.Before;
import org.junit.Test;
import com.block.security.RSACoder;

import java.util.Map;

/**
 * @PROJECT_NAME: blockchain
 * @DESCRIPTION:
 * @USER: eugenechow
 * @DATE: 2020/9/20 8:34 下午
 */
public class RSACoderTest {

    private String publicKey;
    private String privateKey;

    @Before
    public void setUp() throws Exception {
        Map<String, Object> keyMap = RSACoder.genKeyPair();

        publicKey = RSACoder.getPublicKey(keyMap);
        privateKey = RSACoder.getPrivateKey(keyMap);
        System.err.println("公钥: \n\r " + publicKey);
        System.err.println("私钥: \n\r " + privateKey + "\n\r");
    }

    @Test
    public void testEncrypt() throws Exception {
        System.out.println("公钥加密--私钥解密");
        String inputStr = "儿子sb";
        byte[] data = inputStr.getBytes();
        System.out.println(data);
        byte[] encodedData = RSACoder.encryptByPublicKey(data, publicKey);
        byte[] decodedData = RSACoder.decryptByPrivateKey(encodedData, privateKey);

        String outputStr = new String(decodedData);
        System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);

    }

    @Test
    public void testSign() throws Exception {
        System.err.println("私钥签名--公钥验证签名\n");
        String inputStr = "sign";
        byte[] data = inputStr.getBytes();

        // 产生签名
        String sign = RSACoder.sign(data, privateKey);
        System.err.println("签名:" + sign + "\n");

        // 验证签名
        boolean status = RSACoder.verify(data, publicKey, sign);
        System.err.println("状态:" + status);

    }
}
