// src/main/java/crypto/algorithms/symmetric/TripleDESCrypto.java
package crypto.algorithms.symmetric;

import crypto.utils.Constants;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class TripleDESCrypto implements SymmetricCrypto {

    @Override
    public byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    @Override
    public SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(Constants.TRIPLE_DES_ALGORITHM);
        keyGen.init(168, new SecureRandom()); // 3DES使用168位密钥
        return keyGen.generateKey();
    }

    @Override
    public String getAlgorithmName() {
        return "3DES";
    }

    public SecretKey restoreKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, Constants.TRIPLE_DES_ALGORITHM);
    }
}