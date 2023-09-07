package io.github.michaelwilliam0024.fastcryptoutils.Hash;

import java.security.MessageDigest;

import io.github.michaelwilliam0024.fastcryptoutils.Utils.Accelerator;

public class SHA1Algorithm {
    static {
        Accelerator.initialize();
    }

    public static byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }
}
