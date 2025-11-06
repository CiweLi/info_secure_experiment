// src/main/java/crypto/algorithms/signature/DSAManager.java
package crypto.algorithms.signature;

import crypto.core.FileProcessor;
import crypto.core.KeyManager;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DSAManager {
    private KeyManager keyManager;

    public DSAManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    /**
     * 创建新的DSA身份
     */
    public KeyPair createDSAIdentity(String identityName) throws Exception {
        System.out.println("🔐 正在为 '" + identityName + "' 生成DSA密钥对...");
        KeyPair keyPair = DigitalSignature.generateDSAKeyPair();
        keyManager.generateAndSaveDSAKeyPair(identityName);
        System.out.println("✅ DSA身份创建完成: " + identityName);
        return keyPair;
    }

    /**
     * 对文件进行签名
     */
    public byte[] signFile(String filePath, String identityName) throws Exception {
        System.out.println("📝 正在对文件进行数字签名: " + filePath);

        // 加载私钥
        PrivateKey privateKey = keyManager.loadPrivateKey(identityName + "_private", "DSA");

        // 对文件进行签名
        byte[] signature = DigitalSignature.signFile(filePath, privateKey);

        // 保存签名文件
        String signatureFilePath = filePath + ".signature";
        FileProcessor.writeBytesToFile(signature, signatureFilePath);

        System.out.println("✅ 文件签名完成: " + signatureFilePath);
        System.out.println("📊 签名长度: " + signature.length + " bytes");

        return signature;
    }

    /**
     * 验证文件签名
     */
    public boolean verifyFileSignature(String filePath, String signatureFilePath, String identityName)
            throws Exception {
        System.out.println("🔍 正在验证文件签名: " + filePath);

        // 加载公钥
        PublicKey publicKey = keyManager.loadPublicKey(identityName + "_public", "DSA");

        // 读取签名
        byte[] signature = FileProcessor.readFileToBytes(signatureFilePath);

        // 验证签名
        boolean isValid = DigitalSignature.verifyFileSignature(filePath, signature, publicKey);

        if (isValid) {
            System.out.println("✅ 数字签名验证成功！文件完整且可信。");
        } else {
            System.out.println("❌ 数字签名验证失败！文件可能被篡改。");
        }

        return isValid;
    }

    /**
     * 对消息进行签名
     */
    public DigitalSignature.SignatureInfo signMessage(String message, String identityName)
            throws Exception {
        System.out.println("📝 正在对消息进行数字签名...");

        KeyPair keyPair = keyManager.loadDSAKeyPair(identityName);
        byte[] messageBytes = message.getBytes("UTF-8");

        DigitalSignature.SignatureInfo signatureInfo =
                DigitalSignature.generateSignatureWithInfo(messageBytes, keyPair);

        System.out.println("✅ 消息签名完成");
        System.out.println("📊 签名: " + signatureInfo.getSignatureHex());

        return signatureInfo;
    }

    /**
     * 验证消息签名
     */
    public boolean verifyMessage(String message, byte[] signature, String identityName)
            throws Exception {
        System.out.println("🔍 正在验证消息签名...");

        PublicKey publicKey = keyManager.loadPublicKey(identityName + "_public", "DSA");
        byte[] messageBytes = message.getBytes("UTF-8");

        boolean isValid = DigitalSignature.verifySignature(messageBytes, signature, publicKey);

        if (isValid) {
            System.out.println("✅ 消息签名验证成功！消息完整且可信。");
        } else {
            System.out.println("❌ 消息签名验证失败！消息可能被篡改。");
        }

        return isValid;
    }

    /**
     * 完整的签名验证流程示例
     */
    public void demonstrateSignatureWorkflow() throws Exception {
        System.out.println("\n🎯 开始数字签名演示流程...");

        // 1. 创建身份
        String testIdentity = "test_user";
        createDSAIdentity(testIdentity);

        // 2. 创建测试消息
        String testMessage = "这是一条重要的需要签名的消息！";
        String messageFile = "input/test_message.txt";
        FileProcessor.writeStringToFile(testMessage, messageFile);

        // 3. 对消息进行签名
        byte[] signature = signFile(messageFile, testIdentity);

        // 4. 验证签名
        String signatureFile = messageFile + ".signature";
        verifyFileSignature(messageFile, signatureFile, testIdentity);

        // 5. 演示篡改检测
        System.out.println("\n🧪 演示篡改检测...");
        String tamperedMessage = "这是一条被篡改的重要消息！";
        FileProcessor.writeStringToFile(tamperedMessage, "input/tampered_message.txt");

        try {
            verifyFileSignature("input/tampered_message.txt", signatureFile, testIdentity);
        } catch (Exception e) {
            System.out.println("❌ 预期中的验证失败：篡改已被检测到！");
        }

        System.out.println("🎉 数字签名演示完成！");
    }
}