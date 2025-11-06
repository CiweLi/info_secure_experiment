// src/test/java/crypto/CryptoSystemTest.java

import crypto.algorithms.digest.HashGenerator;
import crypto.algorithms.symmetric.AESCrypto;
import crypto.algorithms.symmetric.DESCrypto;
import crypto.algorithms.symmetric.TripleDESCrypto;
import crypto.core.FileProcessor;
import crypto.utils.Conversion;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class CryptoSystemTest {

    private static final String TEST_TEXT = "Hello, Crypto World! 这是加密测试文本。";
    private static final String TEST_FILE = "test_input.txt";
    private static final String ENCRYPTED_FILE = "test_encrypted.dat";
    private static final String DECRYPTED_FILE = "test_decrypted.txt";

    @BeforeAll
    static void setUp() throws Exception {
        // 创建测试文件
        Files.write(Paths.get(TEST_FILE), TEST_TEXT.getBytes("UTF-8"));
    }

    @Test
    void testAESEncryptionDecryption() throws Exception {
        System.out.println("Testing AES Encryption/Decryption...");

        AESCrypto aes = new AESCrypto();
        SecretKey key = aes.generateKey();

        // 加密
        byte[] encrypted = aes.encrypt(TEST_TEXT.getBytes("UTF-8"), key);
        assertNotNull(encrypted);
        assertTrue(encrypted.length > 0);

        // 解密
        byte[] decrypted = aes.decrypt(encrypted, key);
        assertNotNull(decrypted);

        String decryptedText = new String(decrypted, "UTF-8");
        assertEquals(TEST_TEXT, decryptedText);

        System.out.println("✅ AES test passed");
    }

    @Test
    void testDESEncryptionDecryption() throws Exception {
        System.out.println("Testing DES Encryption/Decryption...");

        DESCrypto des = new DESCrypto();
        SecretKey key = des.generateKey();

        byte[] encrypted = des.encrypt(TEST_TEXT.getBytes("UTF-8"), key);
        byte[] decrypted = des.decrypt(encrypted, key);

        String decryptedText = new String(decrypted, "UTF-8");
        assertEquals(TEST_TEXT, decryptedText);

        System.out.println("✅ DES test passed");
    }

    @Test
    void test3DESEncryptionDecryption() throws Exception {
        System.out.println("Testing 3DES Encryption/Decryption...");

        TripleDESCrypto tripleDES = new TripleDESCrypto();
        SecretKey key = tripleDES.generateKey();

        byte[] encrypted = tripleDES.encrypt(TEST_TEXT.getBytes("UTF-8"), key);
        byte[] decrypted = tripleDES.decrypt(encrypted, key);

        String decryptedText = new String(decrypted, "UTF-8");
        assertEquals(TEST_TEXT, decryptedText);

        System.out.println("✅ 3DES test passed");
    }

    @Test
    void testHashGeneration() throws Exception {
        System.out.println("Testing Hash Generation...");

        byte[] data = TEST_TEXT.getBytes("UTF-8");

        // SHA-1
        byte[] sha1Hash = HashGenerator.generateSHA1(data);
        assertNotNull(sha1Hash);
        assertEquals(20, sha1Hash.length); // SHA-1 produces 20 bytes

        String sha1Hex = HashGenerator.generateSHA1Hex(data);
        assertNotNull(sha1Hex);
        assertTrue(sha1Hex.length() > 0);

        // SHA-256
        byte[] sha256Hash = HashGenerator.generateSHA256(data);
        assertNotNull(sha256Hash);
        assertEquals(32, sha256Hash.length); // SHA-256 produces 32 bytes

        String sha256Hex = HashGenerator.generateSHA256Hex(data);
        assertNotNull(sha256Hex);
        assertTrue(sha256Hex.length() > 0);

        System.out.println("✅ Hash generation test passed");
    }

    @Test
    void testFileIntegrity() throws Exception {
        System.out.println("Testing File Integrity...");

        String hash = crypto.algorithms.digest.FileIntegrityChecker.calculateFileHash(TEST_FILE, "SHA-256");
        assertNotNull(hash);
        assertFalse(hash.isEmpty());

        boolean integrityValid = crypto.algorithms.digest.FileIntegrityChecker.verifyFileIntegrity(
                TEST_FILE, hash, "SHA-256");
        assertTrue(integrityValid);

        System.out.println("✅ File integrity test passed");
    }

    @Test
    void testConversionUtilities() throws Exception {
        System.out.println("Testing Conversion Utilities...");

        byte[] testData = TEST_TEXT.getBytes("UTF-8");

        // Hex conversion
        String hex = Conversion.byteArrayToHexString(testData);
        byte[] fromHex = Conversion.hexStringToByteArray(hex);
        assertArrayEquals(testData, fromHex);

        // Base64 conversion
        String base64 = Conversion.byteArrayToBase64String(testData);
        byte[] fromBase64 = Conversion.base64StringToByteArray(base64);
        assertArrayEquals(testData, fromBase64);

        System.out.println("✅ Conversion utilities test passed");
    }

    @Test
    void testFileProcessor() throws Exception {
        System.out.println("Testing File Processor...");

        // Test write and read
        FileProcessor.writeStringToFile(TEST_TEXT, TEST_FILE);
        String readText = FileProcessor.readFileToString(TEST_FILE);
        assertEquals(TEST_TEXT, readText);

        // Test file info
        FileProcessor.FileInfo fileInfo = FileProcessor.getFileInfo(TEST_FILE);
        assertNotNull(fileInfo);
        assertEquals("test_input.txt", fileInfo.getFileName());
        assertTrue(fileInfo.getFileSize() > 0);

        System.out.println("✅ File processor test passed");
    }
}