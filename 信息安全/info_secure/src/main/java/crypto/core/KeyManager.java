package crypto.core;

import crypto.utils.Constants;
import crypto.utils.Conversion;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class KeyManager {
    private Map<String, SecretKey> secretKeyCache;
    private Map<String, KeyPair> keyPairCache;

    public KeyManager() {
        this.secretKeyCache = new HashMap<>();
        this.keyPairCache = new HashMap<>();
    }
    /**
     * 检查密钥是否存在
     */
    public boolean keyExists(String keyName) {
        try {
            File keyFile = new File("keys/secret/" + keyName + ".key");
            return keyFile.exists();
        } catch (Exception e) {
            return false;
        }
    }
    /**
     * 保存对称密钥到文件
     */
    public void saveSecretKey(SecretKey key, String keyName) throws IOException {
        String filePath = "keys/secret/" + keyName + ".key";
        byte[] keyBytes = key.getEncoded();
        FileProcessor.writeBytesToFile(keyBytes, filePath);

        // 缓存密钥
        secretKeyCache.put(keyName, key);
        System.out.println("💾 对称密钥已保存: " + filePath);
    }

    /**
     * 从文件加载对称密钥
     */
    public SecretKey loadSecretKey(String keyName, String algorithm) throws Exception {
        // 检查缓存
        if (secretKeyCache.containsKey(keyName)) {
            return secretKeyCache.get(keyName);
        }

        String filePath = "keys/secret/" + keyName + ".key";
        byte[] keyBytes = FileProcessor.readFileToBytes(filePath);

        javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(
                keyBytes, algorithm);

        secretKeyCache.put(keyName, keySpec);
        System.out.println("🔑 对称密钥已加载: " + filePath);
        return keySpec;
    }

    /**
     * 生成并保存DSA密钥对
     */
    public KeyPair generateAndSaveDSAKeyPair(String keyName) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Constants.DSA_ALGORITHM);
        keyGen.initialize(Constants.DSA_KEY_SIZE);
        KeyPair keyPair = keyGen.generateKeyPair();

        // 保存公钥
        savePublicKey(keyPair.getPublic(), keyName + "_public");
        // 保存私钥
        savePrivateKey(keyPair.getPrivate(), keyName + "_private");

        keyPairCache.put(keyName, keyPair);
        System.out.println("🔐 DSA密钥对已生成并保存: " + keyName);
        return keyPair;
    }

    /**
     * 保存公钥
     */
    public void savePublicKey(PublicKey publicKey, String keyName) throws IOException {
        String filePath = "keys/public/" + keyName + ".pub";
        byte[] keyBytes = publicKey.getEncoded();
        FileProcessor.writeBytesToFile(keyBytes, filePath);
    }

    /**
     * 保存私钥
     */
    public void savePrivateKey(PrivateKey privateKey, String keyName) throws IOException {
        String filePath = "keys/private/" + keyName + ".priv";
        byte[] keyBytes = privateKey.getEncoded();
        FileProcessor.writeBytesToFile(keyBytes, filePath);
    }

    /**
     * 加载公钥
     */
    public PublicKey loadPublicKey(String keyName, String algorithm) throws Exception {
        String filePath = "keys/public/" + keyName + ".pub";
        byte[] keyBytes = FileProcessor.readFileToBytes(filePath);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 加载私钥
     */
    public PrivateKey loadPrivateKey(String keyName, String algorithm) throws Exception {
        String filePath = "keys/private/" + keyName + ".priv";
        byte[] keyBytes = FileProcessor.readFileToBytes(filePath);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 加载DSA密钥对
     */
    public KeyPair loadDSAKeyPair(String keyName) throws Exception {
        if (keyPairCache.containsKey(keyName)) {
            return keyPairCache.get(keyName);
        }

        PublicKey publicKey = loadPublicKey(keyName + "_public", Constants.DSA_ALGORITHM);
        PrivateKey privateKey = loadPrivateKey(keyName + "_private", Constants.DSA_ALGORITHM);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        keyPairCache.put(keyName, keyPair);
        return keyPair;
    }

    /**
     * 列出所有密钥
     */
    public void listKeys() {
        File secretDir = new File("keys/secret");
        File publicDir = new File("keys/public");
        File privateDir = new File("keys/private");

        System.out.println("\n📋 存储的密钥列表:");

        if (secretDir.exists() && secretDir.listFiles() != null) {
            System.out.println("🔑 对称密钥:");
            for (File file : secretDir.listFiles()) {
                System.out.println("  - " + file.getName());
            }
        }

        if (publicDir.exists() && publicDir.listFiles() != null) {
            System.out.println("🔐 公钥:");
            for (File file : publicDir.listFiles()) {
                System.out.println("  - " + file.getName());
            }
        }

        if (privateDir.exists() && privateDir.listFiles() != null) {
            System.out.println("🔒 私钥:");
            for (File file : privateDir.listFiles()) {
                System.out.println("  - " + file.getName());
            }
        }
    }

    /**
     * 删除密钥
     */
    public boolean deleteKey(String keyName, String keyType) {
        String filePath = "keys/" + keyType + "/" + keyName;
        File keyFile = new File(filePath);

        if (keyFile.exists()) {
            boolean deleted = keyFile.delete();
            if (deleted) {
                // 从缓存移除
                if ("secret".equals(keyType)) {
                    secretKeyCache.remove(keyName.replace(".key", ""));
                }
                System.out.println("🗑️ 密钥已删除: " + filePath);
            }
            return deleted;
        }
        return false;
    }
}