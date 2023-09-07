package io.github.michaelwilliam0024.fastcryptoutils;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.michaelwilliam0024.fastcryptoutils.FastCrypto.CryptoUtils;
import io.github.michaelwilliam0024.fastcryptoutils.Crypto.AESAlgorithm;
import io.github.michaelwilliam0024.fastcryptoutils.Crypto.DESAlgorithm;
import io.github.michaelwilliam0024.fastcryptoutils.Crypto.RSAAlgorithm;
import io.github.michaelwilliam0024.fastcryptoutils.Crypto.TripleDESAlgorithm;
import io.github.michaelwilliam0024.fastcryptoutils.Hash.MD5Algorithm;
import io.github.michaelwilliam0024.fastcryptoutils.Hash.MD2Algorithm;
import io.github.michaelwilliam0024.fastcryptoutils.Hash.SHA1Algorithm;
import io.github.michaelwilliam0024.fastcryptoutils.Hash.SHA256Algorithm;
import io.github.michaelwilliam0024.fastcryptoutils.Hash.SHA512Algorithm;
import io.github.michaelwilliam0024.fastcryptoutils.Hash.CRC16Algorithm;
import io.github.michaelwilliam0024.fastcryptoutils.Hash.CRC32Algorithm;

import io.github.michaelwilliam0024.fastcryptoutils.Utils.Accelerator;

public class FastCryptoTest {

    @Test
    public void testRSAEncryptionDecryption() throws Exception {
        // Generate RSA key pair
        KeyPair keyPair = RSAAlgorithm.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String plaintext = "Hello RSA!";

        // Encrypt using public key
        String encrypted = RSAAlgorithm.encrypt(plaintext, publicKey);

        // Decrypt using private key
        String decrypted = RSAAlgorithm.decrypt(encrypted, privateKey);

        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testRSASignatureVerification() throws Exception {
        // Generate RSA key pair
        KeyPair keyPair = RSAAlgorithm.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String message = "Sign this message!";

        // Sign using private key
        String signature = RSAAlgorithm.sign(message, privateKey);

        // Verify signature using public key
        boolean isVerified = RSAAlgorithm.verifySignature(message, signature, publicKey);

        assertTrue(isVerified);
    }
    @Test
    public void testRSAOpenSSLEncryptionDecryption() throws Exception {
        // Generate RSA key pair
        KeyPair keyPair = RSAAlgorithm.generateKeyPair(2048,true);
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String plaintext = "Hello RSA!";

        // Encrypt using public key
        String encrypted = RSAAlgorithm.encrypt(plaintext, publicKey);

        // Decrypt using private key
        String decrypted = RSAAlgorithm.decrypt(encrypted, privateKey);

        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testAESEncryptionDecryption() throws Exception {
        String key = "sampleKey1234567"; // 16 bytes for AES-128
        byte[] iv = "sampleIV12345678".getBytes(); // 16 bytes IV for AES
        String plaintext = "Hello World!";

        String encrypted = AESAlgorithm.encrypt(plaintext, key, "CBC", "PKCS5Padding", iv);
        String decrypted = AESAlgorithm.decrypt(encrypted, key, "CBC", "PKCS5Padding", iv);

        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testDESEncryptionDecryption() throws Exception {
        byte[] key = "sampleKey".getBytes(); // 8 bytes for DES
        byte[] plaintext = "Hello World!".getBytes();

        byte[] encrypted = DESAlgorithm.encrypt(plaintext, key);
        byte[] decrypted = DESAlgorithm.decrypt(encrypted, key);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testTripleDESEncryptionDecryption() throws Exception {
        byte[] key = "sampleKey123sampleKey123".getBytes(); // 24 bytes for TripleDES
        byte[] plaintext = "Hello World!".getBytes();

        byte[] encrypted = TripleDESAlgorithm.encrypt(plaintext, key);
        byte[] decrypted = TripleDESAlgorithm.decrypt(encrypted, key);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testSHA256Hash() throws Exception {
        byte[] data = "Hello World!".getBytes();
        byte[] hash = SHA256Algorithm.hash(data);
        assertArrayEquals(hash,
                CryptoUtils.hexStringToByteArray("7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"));
    }

    @Test
    public void testSHA512Hash() throws Exception {
        byte[] data = "Hello World!".getBytes();
        byte[] hash = SHA512Algorithm.hash(data);
        assertArrayEquals(hash, CryptoUtils.hexStringToByteArray(
                "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"));
    }

    @Test
    public void testMD5Hash() throws Exception {
        byte[] data = "Hello World!".getBytes();
        byte[] hash = MD5Algorithm.hash(data);
        assertArrayEquals(hash, CryptoUtils.hexStringToByteArray("ed076287532e86365e841e92bfc50d8c"));
    }

    @Test
    public void testSHA1Hash() throws Exception {
        byte[] data = "Hello World!".getBytes();
        byte[] hash = SHA1Algorithm.hash(data);
        assertArrayEquals(hash, CryptoUtils.hexStringToByteArray("2ef7bde608ce5404e97d5f042f95f89f1c232871"));
    }

    @Test
    public void testCRC16Hash() {
        byte[] data = "Hello World!".getBytes();
        int expected = 0x57be;
        int result = CRC16Algorithm.hash(data);
        assertEquals(expected, result);
    }

    @Test
    public void testCRC32Hash() {
        byte[] data = "Hello World!".getBytes();
        int expected = 0x1c291ca3;
        int result = CRC32Algorithm.hash(data);
        assertEquals(expected, result);
    }

    @Test
    public void testMD2Hash() throws Exception {
        byte[] data = "Hello World!".getBytes();
        byte[] hash = MD2Algorithm.hash(data);
        assertArrayEquals(hash, CryptoUtils.hexStringToByteArray("315f7c67223f01fb7cab4b95100e872e"));
    }

    @Test
    public void testRSAEncryptionDecryptionWithAcceleator() throws Exception {
        // Wait for initialization to complete
        int retryCount = 0;
        while (!Accelerator.canUseAcceleratedOpenSSL.get()) {
            Thread.sleep(1000);
            retryCount++;
            if (retryCount > 20) {
                System.out.println("This machine is not support accelerate.");
                break;
            }

        }
        // Generate RSA key pair
        KeyPair keyPair = RSAAlgorithm.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String plaintext = "Hello RSA!";

        // Encrypt using public key
        String encrypted = RSAAlgorithm.encrypt(plaintext, publicKey);

        // Decrypt using private key
        String decrypted = RSAAlgorithm.decrypt(encrypted, privateKey);

        assertEquals(plaintext, decrypted);
    }
}
