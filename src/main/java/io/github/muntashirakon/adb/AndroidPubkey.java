// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0
package io.github.muntashirakon.adb;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
//import java.util.Arrays;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.util.encoders.Base64;

public final class AndroidPubkey {
    /**
     * Size of an RSA modulus such as an encrypted block or a signature.
     */
    public static final int ANDROID_PUBKEY_MODULUS_SIZE = 2048/8;

    /**
     * Size of an encoded RSA key.
     */
    public static final int ANDROID_PUBKEY_ENCODED_SIZE = 3*4+2*ANDROID_PUBKEY_MODULUS_SIZE;

    /**
     * Size of the RSA modulus in words.
     */
    public static final int ANDROID_PUBKEY_MODULUS_SIZE_WORDS = ANDROID_PUBKEY_MODULUS_SIZE/4;

    /**
     * The RSA signature padding as an int array.
     */
    private static final int[] SIGNATURE_PADDING_AS_INT = new int[] {
            0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
            0x04, 0x14
    };

    /**
     * The RSA signature padding as a byte array
     */
    private static final byte[] RSA_SHA_PKCS1_SIGNATURE_PADDING;

    static {
        RSA_SHA_PKCS1_SIGNATURE_PADDING = new byte[SIGNATURE_PADDING_AS_INT.length];
        for (int i=0; i<RSA_SHA_PKCS1_SIGNATURE_PADDING.length; i++) {
            RSA_SHA_PKCS1_SIGNATURE_PADDING[i] = (byte)SIGNATURE_PADDING_AS_INT[i];
        } // end for
    } // end static

    /**
     * Signs the ADB SHA1 payload with the private key of this object.
     *
     * @param privateKey Private key to sign with
     * @param payload    SHA1 payload to sign
     * @return Signed SHA1 payload
     * @throws GeneralSecurityException If signing fails
     */
    // Taken from adb_auth_sign
    public static byte[] adbAuthSign(final PrivateKey privateKey, final byte[] payload) throws GeneralSecurityException {
        final Cipher c = Cipher.getInstance("RSA/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, privateKey);
        c.update(RSA_SHA_PKCS1_SIGNATURE_PADDING);
        return c.doFinal(payload);
    } // end adbAuthSign()

    /**
     * Converts a standard RSAPublicKey object to the special ADB format. Available since 4.2.2.
     *
     * @param publicKey RSAPublicKey object to convert
     * @param name      Name without null terminator
     * @return Byte array containing the converted RSAPublicKey object
     */
    public static byte[] encodeWithName(final RSAPublicKey publicKey, final String name) throws InvalidKeyException {
        final int pkeySize = 4*(int)Math.ceil(ANDROID_PUBKEY_ENCODED_SIZE/3.0);
        try (ByteArrayNoThrowOutputStream bos = new ByteArrayNoThrowOutputStream(pkeySize+name.length()+2)) {
            bos.write(Base64.encode(encode(publicKey)));
            bos.write(getUserInfo(name));
            return bos.toByteArray();
        } // end try
    } // end encodeWithName()

    // Taken from get_user_info except that a custom name is used instead of host@user
    static byte[] getUserInfo(final String name) {
        return StringCompat.getBytes(String.format(" %s\u0000", name), "UTF-8");
    } // end getUserInfo()

    // https://android.googlesource.com/platform/system/core/+/e797a5c75afc17024d0f0f488c130128fcd704e2/libcrypto_utils/android_pubkey.cpp
    // typedef struct RSAPublicKey {
    //     uint32_t modulus_size_words;                     // Modulus length. This must be ANDROID_PUBKEY_MODULUS_SIZE.
    //     uint32_t n0inv;                                  // Precomputed montgomery parameter: -1 / n[0] mod 2^32
    //     uint8_t modulus[ANDROID_PUBKEY_MODULUS_SIZE];    // RSA modulus as a little-endian array.
    //     uint8_t rr[ANDROID_PUBKEY_MODULUS_SIZE];         // Montgomery parameter R^2 as a little-endian array.
    //     uint32_t exponent;                               // RSA modulus: 3 or 65537
    // } RSAPublicKey;

    /**
     * Allocates a new {@link RSAPublicKey} object, decodes a public RSA key stored in Android's custom binary format,
     * and sets the key parameters. The resulting key can be used with the standard Java cryptography API to perform
     * public operations.
     *
     * @param androidPubkey Public RSA key in Android's custom binary format. The size of the key must be at least
     *                      {@link #ANDROID_PUBKEY_ENCODED_SIZE}
     * @return {@link RSAPublicKey} object
     */
    public static RSAPublicKey decode(final byte[] androidPubkey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Check size is large enough and the modulus size is correct.
        if (androidPubkey.length<ANDROID_PUBKEY_ENCODED_SIZE) {
            throw new InvalidKeyException("Invalid key length");
        } // end if
        final ByteBuffer keyStruct = ByteBuffer.wrap(androidPubkey).order(ByteOrder.LITTLE_ENDIAN);
        final int modulusSize = keyStruct.getInt();
        if (modulusSize!=ANDROID_PUBKEY_MODULUS_SIZE_WORDS) {
            throw new InvalidKeyException("Invalid modulus length.");
        } // end if

        // Convert the modulus to big-endian byte order as expected by BN_bin2bn.
        final byte[] modulus = new byte[ANDROID_PUBKEY_MODULUS_SIZE];
        keyStruct.position(8);
        keyStruct.get(modulus);
        final BigInteger n = new BigInteger(1, swapEndianness(modulus));

        // Read the exponent.
        keyStruct.position(520);
        final BigInteger e = BigInteger.valueOf(keyStruct.getInt());

        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
        return (RSAPublicKey)keyFactory.generatePublic(publicKeySpec);
    } // end decode()

    /**
     * Encodes the given key in the Android RSA public key binary format.
     *
     * @return Public RSA key in Android's custom binary format. The size of the key should be at least
     * {@link #ANDROID_PUBKEY_ENCODED_SIZE}
     */
    public static byte[] encode(final RSAPublicKey publicKey) throws InvalidKeyException {
    	final byte[] m = publicKey.getModulus().toByteArray();
        if (m.length<ANDROID_PUBKEY_MODULUS_SIZE) {
            throw new InvalidKeyException("Invalid key length "+m.length);
        } // end if
        final ByteBuffer keyStruct = ByteBuffer.allocate(ANDROID_PUBKEY_ENCODED_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        // Store the modulus size.
        keyStruct.putInt(ANDROID_PUBKEY_MODULUS_SIZE_WORDS); // modulus_size_words

        // Compute and store n0inv = -1 / N[0] mod 2^32.
        final BigInteger r32 = BigInteger.ZERO.setBit(32); // r32 = 2^32
        BigInteger n0inv = publicKey.getModulus().mod(r32); // n0inv = N[0] mod 2^32
        n0inv = n0inv.modInverse(r32); // n0inv = 1/n0inv mod 2^32
        n0inv = r32.subtract(n0inv);  // n0inv = 2^32 - n0inv
        keyStruct.putInt(n0inv.intValue()); // n0inv

        // Store the modulus.
        keyStruct.put(Objects.requireNonNull(BigEndianToLittleEndianPadded(ANDROID_PUBKEY_MODULUS_SIZE, publicKey.getModulus())));

        // Compute and store rr = (2^(rsa_size)) ^ 2 mod N.
        BigInteger rr = BigInteger.ZERO.setBit(ANDROID_PUBKEY_MODULUS_SIZE*8); // rr = 2^(rsa_size)
        rr = rr.modPow(BigInteger.valueOf(2), publicKey.getModulus()); // rr = rr^2 mod N
        keyStruct.put(Objects.requireNonNull(BigEndianToLittleEndianPadded(ANDROID_PUBKEY_MODULUS_SIZE, rr)));

        // Store the exponent.
        keyStruct.putInt(publicKey.getPublicExponent().intValue()); // exponent

        return keyStruct.array();
    } // end encode()

    private static byte[] BigEndianToLittleEndianPadded(int len, BigInteger in) {
        final byte[] out = new byte[len];
        final byte[] bytes = swapEndianness(in.toByteArray()); // Convert big endian -> little endian
        int num_bytes = bytes.length;
        if (len<num_bytes) {
            if (!fitsInBytes(bytes, num_bytes, len)) {
                return null;
            } // end if
            num_bytes = len;
        } // end if
        System.arraycopy(bytes, 0, out, 0, num_bytes);
        return out;
    } // end BigEndianToLittleEndianPadded()

    static boolean fitsInBytes(final byte[] bytes, final int num_bytes, final int len) {
        byte mask = 0;
        for (int i=len; i<num_bytes; i++) {
            mask |= bytes[i];
        } // end for
        return mask==0;
    } // end fitsInBytes()

    private static byte[] swapEndianness(byte[] bytes) {
        final int len = bytes.length;
        final byte[] out = new byte[len];
        for (int i=0; i<len; ++i) {
            out[i] = bytes[len-i-1];
        } // end for
        return out;
    } // end swapEndianness()
    
    public static boolean validate(final RSAPublicKey publicKey, final byte[] digest, final byte[] signature) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    	final byte[] decryptedSignature = rsa_decrypt(publicKey, signature);
        if (decryptedSignature.length!=RSA_SHA_PKCS1_SIGNATURE_PADDING.length+digest.length) {
            return false;
        } // end if
        
        for (int i=0; i<RSA_SHA_PKCS1_SIGNATURE_PADDING.length; i++) {
            if (decryptedSignature[i] != RSA_SHA_PKCS1_SIGNATURE_PADDING[i]) {
                return false;
            } // end if
        } // end for
        for (int i=0; i<digest.length; i++) {
            if (decryptedSignature[i+RSA_SHA_PKCS1_SIGNATURE_PADDING.length]!=digest[i]) {
                return false;
            } // end if
        } // end for
        /*
        // use the following and comment out the above if you use Java SE 9+
        if (Arrays.compare(RSA_SHA_PKCS1_SIGNATURE_PADDING, 0, RSA_SHA_PKCS1_SIGNATURE_PADDING.length, decryptedSignature, 0, RSA_SHA_PKCS1_SIGNATURE_PADDING.length)!=0) {
        	return false;
        } // end if
        if (Arrays.compare(digest, 0, digest.length, decryptedSignature, RSA_SHA_PKCS1_SIGNATURE_PADDING.length, decryptedSignature.length)!=0) {
        	return false;
        } // end if
        */
        return true;
    } // end validate()
    
    private static byte[] rsa_decrypt(final RSAPublicKey key, final byte[] signature) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
    	final Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(signature);
    } // end rsa_decrypt()
}

/*
References:
https://github.com/MuntashirAkon/libadb-android/blob/master/libadb/src/main/java/io/github/muntashirakon/adb/AndroidPubkey.java
*/
