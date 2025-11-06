// src/main/java/crypto/algorithms/symmetric/SymmetricCrypto.java
package crypto.algorithms.symmetric;

import javax.crypto.SecretKey;

public interface SymmetricCrypto {
    byte[] encrypt(byte[] data, SecretKey key) throws Exception;
    byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception;
    SecretKey generateKey() throws Exception;
    String getAlgorithmName();
}