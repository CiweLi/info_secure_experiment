// src/main/java/crypto/algorithms/signature/DigitalSignature.java
package crypto.algorithms.signature;

import crypto.utils.Constants;
import crypto.utils.Conversion;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class DigitalSignature {

    /**
     * 生成DSA密钥对
     */
    public static KeyPair generateDSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Constants.DSA_ALGORITHM);
        keyGen.initialize(Constants.DSA_KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    /**
     * 对数据进行数字签名
     */
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(Constants.DSA_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * 验证数字签名
     */
    public static boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey)
            throws Exception {
        Signature signature = Signature.getInstance(Constants.DSA_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    /**
     * 对文件进行数字签名
     */
    public static byte[] signFile(String filePath, PrivateKey privateKey) throws Exception {
        byte[] fileData = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath));
        return signData(fileData, privateKey);
    }

    /**
     * 验证文件的数字签名
     */
    public static boolean verifyFileSignature(String filePath, byte[] signatureBytes, PublicKey publicKey)
            throws Exception {
        byte[] fileData = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath));
        return verifySignature(fileData, signatureBytes, publicKey);
    }

    /**
     * 生成签名并返回详细信息
     */
    public static SignatureInfo generateSignatureWithInfo(byte[] data, KeyPair keyPair)
            throws Exception {
        byte[] signature = signData(data, keyPair.getPrivate());

        return new SignatureInfo(
                signature,
                keyPair.getPublic(),
                keyPair.getPrivate(),
                data.length,
                System.currentTimeMillis()
        );
    }

    /**
     * 从字节数组恢复公钥
     */
    public static PublicKey restorePublicKey(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(Constants.DSA_ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 从字节数组恢复私钥
     */
    public static PrivateKey restorePrivateKey(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(Constants.DSA_ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 签名信息类
     */
    public static class SignatureInfo {
        private byte[] signature;
        private PublicKey publicKey;
        private PrivateKey privateKey;
        private int dataSize;
        private long timestamp;

        public SignatureInfo(byte[] signature, PublicKey publicKey, PrivateKey privateKey,
                             int dataSize, long timestamp) {
            this.signature = signature;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.dataSize = dataSize;
            this.timestamp = timestamp;
        }

        // Getters
        public byte[] getSignature() { return signature; }
        public PublicKey getPublicKey() { return publicKey; }
        public PrivateKey getPrivateKey() { return privateKey; }
        public int getDataSize() { return dataSize; }
        public long getTimestamp() { return timestamp; }

        public String getSignatureHex() {
            return Conversion.byteArrayToHexString(signature);
        }

        public String getPublicKeyBase64() {
            return Conversion.byteArrayToBase64String(publicKey.getEncoded());
        }

        @Override
        public String toString() {
            return String.format(
                    "签名信息: 数据大小=%d bytes, 时间戳=%tF %tT, 签名长度=%d bytes",
                    dataSize, timestamp, timestamp, signature.length
            );
        }
    }
}