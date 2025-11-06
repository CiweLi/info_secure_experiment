// src/main/java/crypto/algorithms/digest/FileIntegrityChecker.java
package crypto.algorithms.digest;

import crypto.utils.Conversion;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;

public class FileIntegrityChecker {

    public static String calculateFileHash(String filePath, String algorithm) throws Exception {
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hashBytes = digest.digest(fileBytes);
        return Conversion.byteArrayToHexString(hashBytes);
    }

    public static boolean verifyFileIntegrity(String filePath, String expectedHash,
                                              String algorithm) throws Exception {
        String actualHash = calculateFileHash(filePath, algorithm);
        return actualHash.equals(expectedHash);
    }

    // 大文件分块计算哈希（处理大文件）
    public static String calculateLargeFileHash(String filePath, String algorithm)
            throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        try (FileInputStream fis = new FileInputStream(new File(filePath))) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = fis.read(buffer)) > 0) {
                digest.update(buffer, 0, count);
            }
        }
        byte[] hashBytes = digest.digest();
        return Conversion.byteArrayToHexString(hashBytes);
    }
}