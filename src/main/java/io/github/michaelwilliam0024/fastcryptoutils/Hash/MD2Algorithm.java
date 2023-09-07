package io.github.michaelwilliam0024.fastcryptoutils.Hash;

import java.security.MessageDigest;

import io.github.michaelwilliam0024.fastcryptoutils.Utils.Accelerator;

public class MD2Algorithm {
    static {
        Accelerator.initialize();
    }

    public static byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD2");
        return md.digest(data);
    }
}
