package io.github.michaelwilliam0024.fastcryptoutils.Crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

import io.github.michaelwilliam0024.fastcryptoutils.Utils.Accelerator;

public class AESAlgorithm {
    static {
        Accelerator.initialize();
    }

    private static final String DEFAULT_MODE = "CBC";
    private static final String DEFAULT_PADDING = "PKCS5Padding";

    public static String encrypt(String plaintext, String key) throws Exception {
        return encrypt(plaintext, key, DEFAULT_MODE, DEFAULT_PADDING, null);
    }

    public static String encrypt(String plaintext, String key, String mode, String padding, byte[] iv) throws Exception {
        String transformation = "AES/" + mode + "/" + padding;
        byte[] keyBytes = key.getBytes("UTF-8");
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance(transformation);
        
        if (iv == null) {
            iv = new byte[16];
            new SecureRandom().nextBytes(iv);
        }
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String ciphertext, String key) throws Exception {
        return decrypt(ciphertext, key, DEFAULT_MODE, DEFAULT_PADDING, null);
    }

    public static String decrypt(String ciphertext, String key, String mode, String padding, byte[] providedIv) throws Exception {
        String transformation = "AES/" + mode + "/" + padding;
        byte[] keyBytes = key.getBytes("UTF-8");
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);

        byte[] iv = new byte[16];
        System.arraycopy(decodedBytes, 0, iv, 0, iv.length);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] encryptedBytes = new byte[decodedBytes.length - 16];
        System.arraycopy(decodedBytes, 16, encryptedBytes, 0, encryptedBytes.length);

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, "UTF-8");
    }
}
