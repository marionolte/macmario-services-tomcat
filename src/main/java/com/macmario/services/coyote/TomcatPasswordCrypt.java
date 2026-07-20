package com.macmario.services.coyote;

import com.macmario.general.Version;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Symmetric password encryption for Tomcat configuration using AES-256-GCM.
 *
 * <p>The 256-bit AES key is derived from a passphrase via SHA-256 (standard JDK only —
 * no external libraries). The encrypted output embeds a random 12-byte IV so each
 * call to {@link #encrypt} produces a different ciphertext for the same input.
 *
 * <p>The passphrase is resolved in this order:
 * <ol>
 *  <li>Value passed to {@link #TomcatPasswordCrypt(String)}</li>
 * </ol>
 *
 * <p>Wire format: {@code Base64( IV[12 bytes] || AES-GCM-ciphertext+tag[n+16 bytes] )}
 */
public class TomcatPasswordCrypt extends Version {

    private static final String CIPHER_ALGO   = "AES/GCM/NoPadding";
    private static final String KEY_ALGO      = "AES";
    private static final String DIGEST_ALGO   = "SHA-256";
    private static final String LocalVAR      = "abc%T&Z/U(I)OBGVFDC";
    private static final String DIGEST_PREFIX = "{SHA}";
    
    private static final int    GCM_IV_BYTES  = 12;
    private static final int    GCM_TAG_BITS  = 128;

    private final byte[] aesKey;

    /** Returns {@code true} when {@code val} was produced by {@link #encrypt} (starts with the digest prefix). */
    public static boolean isEncrypted(String val) {
        return val != null && val.startsWith(DIGEST_PREFIX);
    }

    public static TomcatPasswordCrypt getInstance(String cust) {
        if ( isNullOrEmpty(cust) ) {
            TomcatPasswordCrypt t = new TomcatPasswordCrypt();
            cust=t.resolveSecret();
        }
        return new TomcatPasswordCrypt(cust);
    }
    
    
    /** Resolves the passphrase from {@code TOMCAT_CRYPT_SECRET} env var or {@code -Dtomcat.crypt.secret}. */
    private TomcatPasswordCrypt() {  aesKey=null; }

    
    /** Uses the supplied {@code secret} as the passphrase for key derivation. */
    private TomcatPasswordCrypt(String secret) {
        if ( isNullOrEmpty(secret) ) {
            throw new IllegalArgumentException("Crypt secret must not be blank");
        }
        try {
            this.aesKey = MessageDigest.getInstance(DIGEST_ALGO)                    
                    .digest(secret.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(DIGEST_ALGO + " unavailable in this JVM", e);
        }
    }

    /**
     * Encrypts {@code plaintext} using AES-256-GCM.
     *
     * @return Base64-encoded string containing a random IV and the ciphertext.
     * @throws IllegalArgumentException if encryption fails.
     */
    public String encrypt(String plaintext) {
        if (plaintext == null) throw new IllegalArgumentException("plaintext must not be null");
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(aesKey, KEY_ALGO),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // Prepend IV so decrypt can recover it: [ iv(12) | ciphertext+tag(n+16) ]
            byte[] combined = new byte[GCM_IV_BYTES + ciphertext.length];
            System.arraycopy(iv,         0, combined, 0,            GCM_IV_BYTES);
            System.arraycopy(ciphertext, 0, combined, GCM_IV_BYTES, ciphertext.length);

            return DIGEST_PREFIX+Base64.getEncoder().encodeToString(combined);
        } catch (InvalidAlgorithmParameterException 
                | InvalidKeyException 
                | NoSuchAlgorithmException 
                | BadPaddingException 
                | IllegalBlockSizeException 
                | NoSuchPaddingException e) {
            throw new IllegalArgumentException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts a value previously produced by {@link #encrypt}.
     *
     * @param encrypted Base64-encoded ciphertext from {@code encrypt}.
     * @return the original plaintext.
     * @throws IllegalArgumentException if the input is malformed or the key is wrong.
     */
    public String decrypt(String encrypted) {
        if ( isNullOrEmpty(encrypted)) {
            throw new IllegalArgumentException("encrypted value must not be blank");
        }
        try {
            if ( encrypted.startsWith(DIGEST_PREFIX) ) {  
                encrypted=encrypted.substring(DIGEST_PREFIX.length()); 
            }
            byte[] combined = Base64.getDecoder().decode(encrypted.trim());
            if (combined.length <= GCM_IV_BYTES) {
                throw new IllegalArgumentException("Ciphertext too short — not a valid encrypted value");
            }

            byte[] iv         = new byte[GCM_IV_BYTES];
            byte[] ciphertext = new byte[combined.length - GCM_IV_BYTES];
            System.arraycopy(combined, 0,            iv,         0, GCM_IV_BYTES);
            System.arraycopy(combined, GCM_IV_BYTES, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(aesKey, KEY_ALGO),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));

            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        //} catch (IllegalArgumentException e) {
        //    throw e;
        } catch (IllegalArgumentException | InvalidAlgorithmParameterException 
                | InvalidKeyException 
                | NoSuchAlgorithmException 
                | BadPaddingException 
                | IllegalBlockSizeException 
                | NoSuchPaddingException e) {
            throw new IllegalArgumentException("Decryption failed — wrong key or corrupted ciphertext", e);
        }
    }

    // ── Secret resolution ─────────────────────────────────────────────────────

    private String resolveSecret() {
        Properties p = readPropertyFromRessource("/com/macmario/services/coyote/coyote.properties");
        //System.out.println("p->"+p);
        return p.getProperty("UKEY", LocalVAR);
    }
}
