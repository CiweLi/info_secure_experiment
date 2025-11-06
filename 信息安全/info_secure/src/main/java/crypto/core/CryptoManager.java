// src/main/java/crypto/core/CryptoManager.java
package crypto.core;

import crypto.algorithms.digest.FileIntegrityChecker;
import crypto.algorithms.digest.HashGenerator;
import crypto.algorithms.signature.DSAManager;
import crypto.algorithms.symmetric.AESCrypto;
import crypto.algorithms.symmetric.DESCrypto;
import crypto.algorithms.symmetric.SymmetricCrypto;
import crypto.algorithms.symmetric.TripleDESCrypto;
import crypto.keyexchange.DHKeyExchange;
import crypto.utils.Constants;

import javax.crypto.SecretKey;
import java.io.File;
import java.security.KeyPair;

public class CryptoManager {
    private KeyManager keyManager;
    private DSAManager dsaManager;

    public CryptoManager() {
        this.keyManager = new KeyManager();
        this.dsaManager = new DSAManager(keyManager);
    }

    /**
     * 加密文件
     */
    public void encryptFile(String inputFile, String outputFile, String algorithm, String keyName)
            throws Exception {
        System.out.println("🔒 开始加密文件: " + inputFile);

        // 读取文件内容
        byte[] fileData = FileProcessor.readFileToBytes(inputFile);

        // 获取或生成密钥
        SecretKey key;
        if (keyName != null && keyExists(keyName)) {
            key = keyManager.loadSecretKey(keyName, algorithm);
        } else {
            key = generateSymmetricKey(algorithm);
            if (keyName != null) {
                keyManager.saveSecretKey(key, keyName);
            }
        }

        // 执行加密
        SymmetricCrypto crypto = getSymmetricCrypto(algorithm);
        byte[] encryptedData = crypto.encrypt(fileData, key);

        // 保存加密文件
        FileProcessor.encryptFile(inputFile, outputFile, encryptedData);

        // 计算原文件哈希（用于完整性验证）
        String originalHash = FileIntegrityChecker.calculateFileHash(inputFile, Constants.SHA256_ALGORITHM);
        System.out.println("📊 原文件SHA-256哈希: " + originalHash);

        System.out.println("✅ 文件加密完成: " + outputFile);
    }

    /**
     * 解密文件
     */
    public void decryptFile(String inputFile, String outputFile, String algorithm, String keyName)
            throws Exception {
        System.out.println("🔓 开始解密文件: " + inputFile);

        // 读取加密文件
        byte[] encryptedData = FileProcessor.readFileToBytes(inputFile);

        // 加载密钥
        SecretKey key = keyManager.loadSecretKey(keyName, algorithm);

        // 执行解密
        SymmetricCrypto crypto = getSymmetricCrypto(algorithm);
        byte[] decryptedData = crypto.decrypt(encryptedData, key);

        // 保存解密文件
        FileProcessor.decryptFile(inputFile, outputFile, decryptedData);

        // 计算解密文件哈希
        String decryptedHash = FileIntegrityChecker.calculateFileHash(outputFile, Constants.SHA256_ALGORITHM);
        System.out.println("📊 解密文件SHA-256哈希: " + decryptedHash);

        System.out.println("✅ 文件解密完成: " + outputFile);
    }

    /**
     * 生成对称密钥
     */
    public SecretKey generateSymmetricKey(String algorithm) throws Exception {
        SymmetricCrypto crypto = getSymmetricCrypto(algorithm);
        SecretKey key = crypto.generateKey();
        System.out.println("🔑 生成 " + algorithm + " 密钥成功");
        return key;
    }

    /**
     * 计算文件哈希
     */
    public String calculateFileHash(String filePath, String algorithm) throws Exception {
        String hash = FileIntegrityChecker.calculateFileHash(filePath, algorithm);
        System.out.println("📊 文件 " + filePath + " 的 " + algorithm + " 哈希: " + hash);
        return hash;
    }

    /**
     * 验证文件完整性
     */
    public boolean verifyFileIntegrity(String filePath, String expectedHash, String algorithm)
            throws Exception {
        boolean isValid = FileIntegrityChecker.verifyFileIntegrity(filePath, expectedHash, algorithm);
        if (isValid) {
            System.out.println("✅ 文件完整性验证通过");
        } else {
            System.out.println("❌ 文件完整性验证失败！文件可能被篡改");
        }
        return isValid;
    }

    /**
     * 创建数字签名身份
     */
    public KeyPair createSignatureIdentity(String identityName) throws Exception {
        return dsaManager.createDSAIdentity(identityName);
    }

    /**
     * 对文件进行数字签名
     */
    public byte[] signFile(String filePath, String identityName) throws Exception {
        return dsaManager.signFile(filePath, identityName);
    }

    /**
     * 验证文件签名
     */
    public boolean verifyFileSignature(String filePath, String signatureFile, String identityName)
            throws Exception {
        return dsaManager.verifyFileSignature(filePath, signatureFile, identityName);
    }

    /**
     * 演示Diffie-Hellman密钥交换
     */
    public void demonstrateKeyExchange() throws Exception {
        DHKeyExchange.demonstrateKeyExchange();
    }

    /**
     * 获取对称加密实例
     */
    private SymmetricCrypto getSymmetricCrypto(String algorithm) {
        switch (algorithm.toUpperCase()) {
            case "AES":
                return new AESCrypto();
            case "DES":
                return new DESCrypto();
            case "3DES":
            case "DESEDE":
                return new TripleDESCrypto();
            default:
                throw new IllegalArgumentException("不支持的加密算法: " + algorithm);
        }
    }

    /**
     * 检查密钥是否存在
     */
    private boolean keyExists(String keyName) {
        try {
            // 简单的存在性检查
            File keyFile = new File("keys/secret/" + keyName + ".key");
            return keyFile.exists();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 列出所有功能
     */
    public void listCapabilities() {
        System.out.println("\n🎯 加密系统功能列表:");
        System.out.println("🔐 对称加密: AES, DES, 3DES");
        System.out.println("📊 哈希算法: SHA-1, SHA-256");
        System.out.println("✍️  数字签名: DSA");
        System.out.println("🔑 密钥交换: Diffie-Hellman");
        System.out.println("📁 文件操作: 加密/解密/哈希计算/完整性验证");
        System.out.println("🔑 密钥管理: 生成/保存/加载/列表");
    }

    /**
     * 系统状态检查
     */
    public void systemStatus() {
        System.out.println("\n📊 系统状态检查:");

        // 检查目录
        String[] dirs = {"input", "output", "keys", "keys/secret", "keys/public", "keys/private"};
        for (String dir : dirs) {
            File directory = new File(dir);
            System.out.println((directory.exists() ? "✅ " : "❌ ") + dir + " 目录");
        }

        // 列出密钥
        keyManager.listKeys();
    }
}