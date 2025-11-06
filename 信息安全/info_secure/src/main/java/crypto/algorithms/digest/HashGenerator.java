// src/main/java/crypto/algorithms/digest/HashGenerator.java
package crypto.algorithms.digest;

import crypto.utils.Conversion;

import java.security.MessageDigest;

public class HashGenerator {

    public static byte[] generateSHA1(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        return digest.digest(data);
    }

    public static byte[] generateSHA256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    public static String generateSHA1Hex(byte[] data) throws Exception {
        byte[] digest = generateSHA1(data);
        return Conversion.byteArrayToHexString(digest);
    }

    public static String generateSHA256Hex(byte[] data) throws Exception {
        byte[] digest = generateSHA256(data);
        return Conversion.byteArrayToHexString(digest);
    }

    public static boolean verifyIntegrity(byte[] data, byte[] expectedDigest, String algorithm)
            throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] actualDigest = digest.digest(data);
        return MessageDigest.isEqual(actualDigest, expectedDigest);
    }
}