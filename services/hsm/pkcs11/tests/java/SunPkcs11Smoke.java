// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// SunPkcs11Smoke drives libkythira_pkcs11.so from Java's SunPKCS11
// provider (.kiro/specs/virtual-hsm/ task 10b, requirement 5.6): an EC key
// pair generated on the token signs with SHA256withECDSA and verifies with
// the JDK's own provider, the key store lists it, and an AES key encrypts
// and decrypts with AES/GCM/NoPadding. Run as a single source file:
//   java SunPkcs11Smoke.java <sunpkcs11.cfg> <user pin>

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class SunPkcs11Smoke {
    public static void main(String[] args) throws Exception {
        Provider p = Security.getProvider("SunPKCS11").configure(args[0]);
        Security.addProvider(p);
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, args[1].toCharArray());
        System.out.println("provider: " + p.getName() + ", entries: "
                + Collections.list(ks.aliases()));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", p);
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = kpg.generateKeyPair();
        byte[] data = "signed from java".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withECDSA", p);
        signer.initSign(pair.getPrivate());
        signer.update(data);
        byte[] sig = signer.sign();
        // The JDK's own provider, not the token, checks the signature.
        Signature verifier = Signature.getInstance("SHA256withECDSA", "SunEC");
        verifier.initVerify(pair.getPublic());
        verifier.update(data);
        check(verifier.verify(sig), "the token's signature does not verify");

        KeyGenerator kg = KeyGenerator.getInstance("AES", p);
        kg.init(256);
        SecretKey key = kg.generateKey();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", p);
        enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        enc.updateAAD("aad".getBytes(StandardCharsets.UTF_8));
        byte[] plain = "sealed from java".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = enc.doFinal(plain);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", p);
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        dec.updateAAD("aad".getBytes(StandardCharsets.UTF_8));
        check(Arrays.equals(dec.doFinal(sealed), plain), "GCM round trip differs");
        sealed[0] ^= 1;
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        dec.updateAAD("aad".getBytes(StandardCharsets.UTF_8));
        try {
            dec.doFinal(sealed);
            check(false, "GCM opened tampered bytes");
        } catch (AEADBadTagException expected) {
            // The tag check failed, as it must.
        }
        System.out.println("SunPkcs11Smoke: ok");
    }

    private static void check(boolean ok, String why) {
        if (!ok) {
            throw new IllegalStateException(why);
        }
    }
}
