package io.github.michaelwilliam0024.fastcryptoutils.Crypto;

import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import java.util.Base64;

import io.github.michaelwilliam0024.fastcryptoutils.FastCrypto;
import io.github.michaelwilliam0024.fastcryptoutils.Utils.Accelerator;

public class RSAAlgorithm {
    static {
        Accelerator.initialize();
    }

    public static KeyPair generateKeyPair() throws Exception {
        return generateKeyPair(2048, false);
    }

    public static KeyPair generateKeyPair(int keySize,boolean forceOpenSSL) throws Exception {
        if (Accelerator.canUseAcceleratedOpenSSL.get() || forceOpenSSL) {
            // Step 1: Generate RSA private key using openssl
            String command = "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:" + keySize;
            Process process = Runtime.getRuntime().exec(command);
            byte[] privateKeyPEM = FastCrypto.CryptoUtils.readStream(process.getInputStream());
            process.waitFor();
        
            // Convert PEM private key to PKCS#8 DER format
            command = "openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt";
            process = Runtime.getRuntime().exec(command);
            try (OutputStream os = process.getOutputStream()) {
                os.write(privateKeyPEM);
                os.flush();
            }
            byte[] privateKeyBytes = FastCrypto.CryptoUtils.readStream(process.getInputStream());
            process.waitFor();
        
            // Convert private key bytes to PrivateKey object
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        
            // Step 2: Extract RSA public key from private key using openssl in DER format
            command = "openssl rsa -pubout -inform PEM -outform DER";
            process = Runtime.getRuntime().exec(command);
            try (OutputStream os = process.getOutputStream()) {
                os.write(privateKeyPEM);
                os.flush();
            }
            byte[] publicKeyBytes = FastCrypto.CryptoUtils.readStream(process.getInputStream());
            process.waitFor();
        
            // Convert public key bytes to PublicKey object
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        
            return new KeyPair(publicKey, privateKey);
        }
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    public static String encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, "UTF-8");
    }

    public static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes("UTF-8"));
        byte[] signedBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signedBytes);
    }

    public static boolean verifySignature(String message, String signatureData, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes("UTF-8"));
        byte[] signatureBytes = Base64.getDecoder().decode(signatureData);
        return signature.verify(signatureBytes);
    }
}
