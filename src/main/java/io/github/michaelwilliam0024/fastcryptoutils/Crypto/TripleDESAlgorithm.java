package io.github.michaelwilliam0024.fastcryptoutils.Crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import io.github.michaelwilliam0024.fastcryptoutils.Utils.Accelerator;

public class TripleDESAlgorithm {
    static {
        Accelerator.initialize();
    }

    public static byte[] encrypt(byte[] plaintext, byte[] key) throws Exception {
        DESedeKeySpec desedeKeySpec = new DESedeKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(desedeKeySpec);

        Cipher cipher = Cipher.getInstance("DESede");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) throws Exception {
        DESedeKeySpec desedeKeySpec = new DESedeKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(desedeKeySpec);

        Cipher cipher = Cipher.getInstance("DESede");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(ciphertext);
    }
}
