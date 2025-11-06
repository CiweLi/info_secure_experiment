// src/main/java/crypto/keyexchange/DHKeyExchange.java
package crypto.keyexchange;

import crypto.utils.Conversion;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class DHKeyExchange {

    /**
     * Alice生成DH密钥对
     */
    public static KeyPair generateAliceKeyPair() throws Exception {
        System.out.println("👩 Alice正在生成DH密钥对...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(512);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
        System.out.println("✅ Alice密钥对生成完成");
        return aliceKpair;
    }

    /**
     * Bob根据Alice的公钥生成DH密钥对
     */
    public static KeyPair generateBobKeyPair(PublicKey alicePublicKey) throws Exception {
        System.out.println("👨 Bob正在根据Alice的公钥生成DH密钥对...");

        // 从Alice的公钥获取DH参数
        DHParameterSpec dhParamSpec = ((javax.crypto.interfaces.DHPublicKey) alicePublicKey).getParams();

        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamSpec);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        System.out.println("✅ Bob密钥对生成完成");
        return bobKpair;
    }

    /**
     * 生成共享密钥
     */
    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey otherPublicKey,
                                                 String algorithm) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(otherPublicKey, true);
        return keyAgree.generateSecret(algorithm);
    }

    /**
     * 完整的DH密钥交换演示
     */
    public static void demonstrateKeyExchange() throws Exception {
        System.out.println("\n🔑 开始Diffie-Hellman密钥交换演示...");

        // Alice生成密钥对
        KeyPair aliceKeyPair = generateAliceKeyPair();
        PublicKey alicePubKey = aliceKeyPair.getPublic();
        PrivateKey alicePrivKey = aliceKeyPair.getPrivate();

        System.out.println("📤 Alice发送公钥给Bob...");

        // Bob根据Alice的公钥生成密钥对
        KeyPair bobKeyPair = generateBobKeyPair(alicePubKey);
        PublicKey bobPubKey = bobKeyPair.getPublic();
        PrivateKey bobPrivKey = bobKeyPair.getPrivate();

        System.out.println("📤 Bob发送公钥给Alice...");

        // Alice生成共享密钥
        System.out.println("🔐 Alice正在生成共享密钥...");
        SecretKey aliceSharedKey = generateSharedSecret(alicePrivKey, bobPubKey, "DES");
        System.out.println("👩 Alice的共享密钥: " +
                Conversion.byteArrayToHexString(aliceSharedKey.getEncoded()));

        // Bob生成共享密钥
        System.out.println("🔐 Bob正在生成共享密钥...");
        SecretKey bobSharedKey = generateSharedSecret(bobPrivKey, alicePubKey, "DES");
        System.out.println("👨 Bob的共享密钥: " +
                Conversion.byteArrayToHexString(bobSharedKey.getEncoded()));

        // 验证密钥是否相同
        boolean keysMatch = Conversion.byteArrayToHexString(aliceSharedKey.getEncoded())
                .equals(Conversion.byteArrayToHexString(bobSharedKey.getEncoded()));

        if (keysMatch) {
            System.out.println("✅ 成功！Alice和Bob生成了相同的共享密钥！");
        } else {
            System.out.println("❌ 失败！共享密钥不匹配！");
        }

        System.out.println("🎉 Diffie-Hellman密钥交换演示完成！");
    }

    /**
     * 获取DH密钥交换参与者
     */
    public static class DHParticipant {
        private String name;
        private KeyPair keyPair;
        private SecretKey sharedKey;

        public DHParticipant(String name) {
            this.name = name;
        }

        public void generateKeyPair() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(512);
            this.keyPair = kpg.generateKeyPair();
        }

        public void generateKeyPair(DHParameterSpec dhParams) throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhParams);
            this.keyPair = kpg.generateKeyPair();
        }

        public void generateSharedKey(PublicKey otherPublicKey, String algorithm) throws Exception {
            this.sharedKey = generateSharedSecret(keyPair.getPrivate(), otherPublicKey, algorithm);
        }

        // Getters
        public String getName() { return name; }
        public KeyPair getKeyPair() { return keyPair; }
        public PublicKey getPublicKey() { return keyPair.getPublic(); }
        public SecretKey getSharedKey() { return sharedKey; }

        @Override
        public String toString() {
            return String.format("参与者: %s, 公钥: %s...",
                    name, Conversion.byteArrayToHexString(keyPair.getPublic().getEncoded()).substring(0, 16));
        }
    }
}