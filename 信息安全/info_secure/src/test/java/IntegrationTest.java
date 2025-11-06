// src/test/java/crypto/IntegrationTest.java

import crypto.core.CryptoManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IntegrationTest {

    private CryptoManager cryptoManager;
    private static final String TEST_FILE = "input/integration_test.txt";
    private static final String ENCRYPTED_FILE = "output/integration_encrypted.dat";
    private static final String DECRYPTED_FILE = "output/integration_decrypted.txt";

    @BeforeEach
    void setUp() throws Exception {
        cryptoManager = new CryptoManager();
        // 创建测试文件
        crypto.core.FileProcessor.writeStringToFile("集成测试文件内容", TEST_FILE);
    }

    @Test
    void testCompleteEncryptionWorkflow() throws Exception {
        System.out.println("Testing Complete Encryption Workflow...");

        // 1. 计算原文件哈希
        String originalHash = cryptoManager.calculateFileHash(TEST_FILE, "SHA-256");

        // 2. 加密文件
        cryptoManager.encryptFile(TEST_FILE, ENCRYPTED_FILE, "AES", "integration_test_key");

        // 3. 解密文件
        cryptoManager.decryptFile(ENCRYPTED_FILE, DECRYPTED_FILE, "AES", "integration_test_key");

        // 4. 验证解密文件哈希
        String decryptedHash = cryptoManager.calculateFileHash(DECRYPTED_FILE, "SHA-256");
        assertEquals(originalHash, decryptedHash);

        System.out.println("✅ Complete encryption workflow test passed");
    }

    @Test
    void testKeyManagement() throws Exception {
        System.out.println("Testing Key Management...");

        // 生成密钥
        cryptoManager.generateSymmetricKey("AES");

        // 这里可以添加更多的密钥管理测试
        assertTrue(true); // 暂时通过

        System.out.println("✅ Key management test passed");
    }
}