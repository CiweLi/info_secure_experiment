// src/main/java/crypto/utils/Conversion.java
package crypto.utils;

import java.util.Base64;

public class Conversion {

    public static String byteArrayToHexString(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] hexStringToByteArray(String hex) {
        if (hex == null || hex.length() == 0) return new byte[0];
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static String byteArrayToBase64String(byte[] bytes) {
        if (bytes == null) return "";
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] base64StringToByteArray(String base64) {
        if (base64 == null || base64.isEmpty()) return new byte[0];
        return Base64.getDecoder().decode(base64);
    }
}