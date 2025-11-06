// src/main/java/crypto/algorithms/symmetric/AESCrypto.java
package crypto.algorithms.symmetric;

import crypto.utils.Constants;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AESCrypto implements SymmetricCrypto {

    @Override
    public byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(Constants.AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(Constants.AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    @Override
    public SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(Constants.AES_ALGORITHM);
        keyGen.init(Constants.AES_KEY_SIZE, new SecureRandom());
        return keyGen.generateKey();
    }

    @Override
    public String getAlgorithmName() {
        return "AES";
    }

    // 从字节数组恢复密钥
    public SecretKey restoreKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, Constants.AES_ALGORITHM);
    }
}