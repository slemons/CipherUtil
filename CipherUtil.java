package org.example;



import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

/**
 * Utility that helps with encryption and decryption.
 */
public final class CipherUtil {

    private static final Logger log = LogManager.getLogger(CipherUtil.class.getName());

    /**
     * Name of the keystore.
     */
    static final String DEFAULT_KEYSTORE_NAME = "cipher-keystore.bcfks";
    /**
     * Alias for the KeySecret within the KeyStore.
     */
    static final String KEYSECRET_ALIAS = "cipherKeySecret";
    /**
     * The keystore type used.
     */
    static final String KEYSTORE_TYPE = "BCFKS";
    /**
     * Name of the Cipher algorithm Provider.
     */
    static final String CIPHER_ALGO_PROVIDER = "BCFIPS";
    /**
     * Charset to use for decoding/encoding bytes.
     */
    static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
    /**
     * The algorithm to use for encryption/decryption
     */
    private static final String CIPHER_ALGO = "AES/GCM/NoPadding";
    /**
     * The shortname for the algorithm.
     */
    private static final String CIPHER_ALGO_SHORT_NAME = "AES";
    /**
     * Length of the Initialization Vector.
     */
    private static final int INIT_VECTOR_LENGTH = 16;
    /**
     * The authentication tag length (in bits)
     */
    private static final int GCM_TAG_LENGTH = 128;
    /**
     * The SecretKey size. This is an algorithm-specific metric, specified in number of bits.
     */
    private static final int SECRET_KEY_SIZE = 128;
    /**
     * Nonce value used in generation of random numbers.
     */
    private static final byte[] NONCE = UUID.randomUUID().toString().getBytes();
    /**
     * The required security strength for the SecureRandom.
     */
    private static final int SECURE_RANDOM_SEC_STRENGTH = 256;
    /**
     * The required number of entropy bits for the SecureRandom.
     */
    private static final int SECURE_RANDOM_REQ_ENT_BITS = 256;

    /**
     * Default Constructor.
     */
    public CipherUtil() {
        // Sets the default SecureRandom number generator to use BouncyCastle FIPS generator.
        CryptoServicesRegistrar.setSecureRandom(CipherUtil.createSecureRandom());
    }

    /**
     * Creates a FIPS compliant SecureRandom instance.
     *
     * @return the created SecureRandom instance.
     */
    private static SecureRandom createSecureRandom() {
        return FipsDRBG.SHA512_HMAC.fromEntropySource(
                        new BasicEntropySourceProvider(new SecureRandom(), true))
                .setSecurityStrength(SECURE_RANDOM_SEC_STRENGTH)
                .setEntropyBitsRequired(SECURE_RANDOM_REQ_ENT_BITS).build(NONCE, false);
    }

    /**
     * Converts a byte[] to a char[] using the default charset.
     *
     * @param byteArray the provided byte[]
     * @return the resulting char[]
     */
    private static char[] fromByteToCharArrayConverter(byte[] byteArray) {
        ByteBuffer buffer = ByteBuffer.wrap(byteArray);
        CharBuffer charBuffer = CipherUtil.DEFAULT_CHARSET.decode(buffer);

        char[] charArray = new char[charBuffer.remaining()];
        charBuffer.get(charArray);

        return charArray;
    }

    /**
     * Converts a char[] to a byte array using the default charset.
     *
     * @param charArray the provided char[]
     * @return the resulting byte[]
     */
    private static byte[] fromCharToByteArray(char[] charArray) {
        CharBuffer charBuffer = CharBuffer.wrap(charArray);
        ByteBuffer byteBuffer = CipherUtil.DEFAULT_CHARSET.encode(charBuffer);

        byte[] byteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(byteArray);

        return byteArray;
    }

    /**
     * Generates a SecretKey for use with the Encrypt and Decrypt methods using the same cipher logarithm.
     *
     * @return the generated SecretKey
     *
     * @throws NoSuchAlgorithmException
     *         thrown if classloader cannot load the algorithm required.
     */
    public SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        // Setup generator.
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_ALGO_SHORT_NAME);
        keyGenerator.init(SECRET_KEY_SIZE);

        // Generate Key
        return keyGenerator.generateKey();
    }

    /**
     * Load the secret key for this utilities encryption and decryption from the keystore.
     *
     * @param keystoreLoc the location of the Keystore to load
     * @param keystorePass the password for the Keystore
     *
     * @return the loaded SecretKey, or null if not found
     *
     * @throws KeyStoreException thrown is cant load the keystore
     * @throws IOException thrown if cannot load the keystore from the filesystem
     * @throws CertificateException thrown if cannot load the key from the keystore
     * @throws NoSuchAlgorithmException thrown if the parameters for the keystore is wrong.
     * @throws UnrecoverableKeyException thrown if the key cannot be read for some reason
     */
    public SecretKey loadSecretKey(final String keystoreLoc, final char[] keystorePass)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException, NoSuchProviderException {
        return this.loadSecretKey(new FileInputStream(keystoreLoc), keystorePass);
    }

    /**
     * Load the secret key for this utilities encryption and decryption from the keystore.
     *
     * @param keystoreStream a non-closed input stream to the keystore file
     * @param keystorePass the password for the Keystore
     *
     * @return the loaded SecretKey, or null if not found. Provided inputstream is closed.
     *
     * @throws KeyStoreException thrown is cant load the keystore
     * @throws IOException thrown if cannot load the keystore from the filesystem
     * @throws CertificateException thrown if cannot load the key from the keystore
     * @throws NoSuchAlgorithmException thrown if the parameters for the keystore is wrong.
     * @throws UnrecoverableKeyException thrown if the key cannot be read for some reason
     */
    public SecretKey loadSecretKey(final FileInputStream keystoreStream, final char[] keystorePass)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException, NoSuchProviderException {
        final KeyStore ks = KeyStore.getInstance(CipherUtil.KEYSTORE_TYPE,
                CipherUtil.CIPHER_ALGO_PROVIDER);
        try(final FileInputStream is = keystoreStream) {
            ks.load(is, keystorePass);
        }

        return(SecretKey) ks.getKey(CipherUtil.KEYSECRET_ALIAS,
                StringUtils.EMPTY.toCharArray());
    }

    /**
     * Creates a secure Initializing Vector (IV) value for use in encryption and decryption.
     *
     * @return the created IV value.
     */
    public byte[] generateInitializingVector() {
        final byte[] IV = new byte[INIT_VECTOR_LENGTH];
        CipherUtil.createSecureRandom().nextBytes(IV);

        return IV;
    }

    /**
     * Encrypts a plaintext String using the provided secret key and initializing vector.
     * Returns the encrypted result combined with the IV.
     *
     * @param plaintext the text to encrypt.
     * @param key the secret key to use for encryption
     * @param IV the initializing vector to use for encryption
     *
     * @return a byte[] containing [IV] + [encrypted value]
     *
     * @throws NoSuchPaddingException thrown if cannot apply the padding algorithm selected
     * @throws NoSuchAlgorithmException thrown if cannot find a provider for the algorithm selected
     * @throws IOException thrown if cannot decode the provided plaintext using the configured CharSet
     * @throws IllegalBlockSizeException thrown if the selected block size is not available with the selected algorithm
     * @throws BadPaddingException thrown if the padding selected does not work with the selected algorithm.
     * @throws InvalidAlgorithmParameterException thrown if the parameters selected for the cipher algorithm are invalid.
     * @throws InvalidKeyException thrown if the secret key provided is invalid.
     * @throws NoSuchProviderException thrown if the cipher algorithm provider selected is not available.
     */
    public byte[] encrypt(final String plaintext, final SecretKey key, final byte[] IV)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IOException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
            InvalidKeyException, NoSuchProviderException {
        byte[] result;

        //Create SecretKeySpec
        final SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), CIPHER_ALGO_SHORT_NAME);

        //Create GCMParameterSpec
        final GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, IV);

        //Get Cipher Instance
        final Cipher cipher = Cipher.getInstance(CIPHER_ALGO, CIPHER_ALGO_PROVIDER);

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        //Perform Encryption
        final byte[] cipherText = cipher.doFinal(CipherUtil.fromCharToByteArray(plaintext.toCharArray()));

        // combine results and auto-close stream
        try (final ByteArrayOutputStream b = new ByteArrayOutputStream()) {
            b.write(IV);
            b.write(cipherText);

            result = b.toByteArray();
        }

        return result;
    }

    /**
     * Encrypts a plaintext String using the provided secret key and initializing vector.
     * Returns the encrypted result combined with the IV.
     *
     * @param plaintext the text to encrypt.
     * @param keystorePass the password of the keystore

     *
     * @return the encrypted text in Base64 encoding
     *
     * @throws NoSuchPaddingException thrown if cannot apply the padding algorithm selected
     * @throws NoSuchAlgorithmException thrown if cannot find a provider for the algorithm selected
     * @throws IOException thrown if cannot decode the provided plaintext using the configured CharSet
     * @throws IllegalBlockSizeException thrown if the selected block size is not available with the selected algorithm
     * @throws BadPaddingException thrown if the padding selected does not work with the selected algorithm.
     * @throws InvalidAlgorithmParameterException thrown if the parameters selected for the cipher algorithm are invalid.
     * @throws InvalidKeyException thrown if the secret key provided is invalid.
     * @throws NoSuchProviderException thrown if the cipher algorithm provider selected is not available.
     * @throws UnrecoverableKeyException thrown if a key in the keystore cannot be recovered.
     * @throws CertificateException
     * @throws KeyStoreException
     */
    public String encrypt(final String plaintext, final String keystorePass)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IOException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
            InvalidKeyException, NoSuchProviderException, UnrecoverableKeyException, CertificateException, KeyStoreException {

        final byte[] initVector = generateInitializingVector();
        final URL keyFile = this.getClass().getClassLoader().getResource(CipherUtil.DEFAULT_KEYSTORE_NAME);
        try (final FileInputStream stream =
                     new FileInputStream(new File(CipherUtil.DEFAULT_KEYSTORE_NAME))) {
            SecretKey key = loadSecretKey(stream,keystorePass.toCharArray());
            final byte[] encryptedText = encrypt(plaintext, key, initVector);

            String encryptedTextBase64 = Base64.getEncoder().encodeToString(encryptedText);

            return encryptedTextBase64;
        }

    }


    /**
     * Decode the provided cipher text into it's plaintext form using the configured cipher provider and algorithm.
     *
     * @param cipherText the text to decrypt.
     * @param key the key to use to decrypt.
     *
     * @return the decrypted plain text
     *
     * @throws NoSuchPaddingException thrown if annot apply the padding algorithm selected
     * @throws NoSuchAlgorithmException thrown if cannot find a provider for the algorithm selected
     * @throws InvalidAlgorithmParameterException thrown if the parameters selected for the cipher algorithm are invalid.
     * @throws InvalidKeyException thrown if the secret key provided is invalid.
     * @throws IllegalBlockSizeException thrown if the selected block size is not available with the selected algorithm
     * @throws BadPaddingException thrown if the padding selected does not work with the selected algorithm.
     * @throws NoSuchProviderException thrown if the cipher algorithm provider selected is not available.
     */
    public char[] decrypt(byte[] cipherText, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException,
            NoSuchFieldException, IllegalAccessException {
        // create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), CIPHER_ALGO_SHORT_NAME);

        // create GCMParameterSpec
        final GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, cipherText,
                0, INIT_VECTOR_LENGTH);

        // remove the GCMParam to get just what was encrypted
        final byte[] justCipherText = java.util.Arrays.copyOfRange(cipherText, INIT_VECTOR_LENGTH,
                cipherText.length);

        // get Cipher Instance
        final Cipher cipher = Cipher.getInstance(CIPHER_ALGO, CIPHER_ALGO_PROVIDER);

        // initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        // perform decryption and return
        final byte[] decryptedBytes = cipher.doFinal(justCipherText);

        // clean up
        keySpec = null;
        key = null;

        // return result
        return CipherUtil.fromByteToCharArrayConverter(decryptedBytes);
    }

    /**
     * Decrypts the provided password using the default settings for this utility.
     * <br/>
     * Only works if the password was encrypted with this same utility and if the SecretKey
     * stored in the Keystore has not changed.
     *
     * @param encryptedText the encrypted bytes that is the [iv]+[password]
     * @param keystorePass the password to the keystore the SecretKey is stored in
     * @return the decrypted password portion of the provided encryptedText value.
     */
    public char[] decryptPassword(final byte[] encryptedText, final char[] keystorePass) {
        char[] result = new char[0];

        if(ArrayUtils.isEmpty(encryptedText) || ArrayUtils.isEmpty(keystorePass)) {
            log.warn("Cannot decrypt encrypted password if the password is empty of no keystore password is provided.");
        } else {
            log.debug("Decrypting password using default keystore: {}", ()->DEFAULT_KEYSTORE_NAME);
            final URL keystoreFile = this.getClass().getClassLoader().getResource(CipherUtil.DEFAULT_KEYSTORE_NAME);
            if(null != keystoreFile) {
                try (final FileInputStream fis = new FileInputStream(new File(CipherUtil.DEFAULT_KEYSTORE_NAME))) {
                    // decrypt password
                    result = this.decrypt(encryptedText,
                            this.loadSecretKey(fis, keystorePass));
                    log.debug("Successfully decrypted password");
                } catch (IOException e) {
                    log.warn("Cannot load keystore at from resources with name: {}, exception: {}",
                            ()->DEFAULT_KEYSTORE_NAME, e::getMessage);
                } catch (UnrecoverableKeyException | CertificateException | KeyStoreException |
                         NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException |
                         InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException |
                         BadPaddingException | NoSuchFieldException | IllegalAccessException e) {
                    log.warn("Cannot decrypt password, cipher, keystore, or key are misconfigured: {}",
                            e::getMessage);
                }
            } else {
                log.warn("Cannot load default keystore file {}, cannot decrypt.",
                        ()-> DEFAULT_KEYSTORE_NAME);

            }
        }

        return result;
    }

    /**
     * Encrypts a plaintext String using the provided secret key and initializing vector.
     * Returns the encrypted result combined with the IV.
     *
     * @param encryptedTextBase64 the encrypted text Base64 encoded to decrypt
     * @param keystorePass the password of the keystore

     *
     * @return the encrypted text in Base64 encoding
     *
     * @throws NoSuchPaddingException thrown if cannot apply the padding algorithm selected
     * @throws NoSuchAlgorithmException thrown if cannot find a provider for the algorithm selected
     * @throws IOException thrown if cannot decode the provided plaintext using the configured CharSet
     * @throws IllegalBlockSizeException thrown if the selected block size is not available with the selected algorithm
     * @throws BadPaddingException thrown if the padding selected does not work with the selected algorithm.
     * @throws InvalidAlgorithmParameterException thrown if the parameters selected for the cipher algorithm are invalid.
     * @throws InvalidKeyException thrown if the secret key provided is invalid.
     * @throws NoSuchProviderException thrown if the cipher algorithm provider selected is not available.
     * @throws UnrecoverableKeyException thrown if a key in the keystore cannot be recovered.
     * @throws CertificateException
     * @throws KeyStoreException
     */
    public String decryptPassword(final String encryptedTextBase64, final String keystorePass)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IOException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
            InvalidKeyException, NoSuchProviderException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchFieldException, IllegalAccessException {


            final byte[] initVector = generateInitializingVector();
            final URL keyFile = this.getClass().getClassLoader().getResource(CipherUtil.DEFAULT_KEYSTORE_NAME);
            try (final FileInputStream stream =
                         new FileInputStream(new File(CipherUtil.DEFAULT_KEYSTORE_NAME))) {
                SecretKey key = loadSecretKey(stream, keystorePass.toCharArray());
                byte[] encryptedText2 = Base64.getDecoder().decode(encryptedTextBase64);

                final String plainText = new String(decrypt(encryptedText2, key));

                return plainText;
            }
    }

    /**
     * Utility for creating a blank keystore and creating a SecretKey in the keyStore
     * in the correct format for use for password encryption and decryption.
     *
     * @throws KeyStoreException if cannot create keystore
     * @throws NoSuchProviderException if cannot load defined provider
     * @throws IOException if cannot read or save file location defined
     * @throws CertificateException if cannot read keystore
     * @throws NoSuchAlgorithmException if cannot use the algorithm defined.
     */
    void generateKeystore(final String keystorePass) throws KeyStoreException,
            NoSuchProviderException, IOException, CertificateException, NoSuchAlgorithmException {
        final File newStore = new File(CipherUtil.DEFAULT_KEYSTORE_NAME);

        final KeyStore keyStore = KeyStore.getInstance(CipherUtil.KEYSTORE_TYPE,
                CipherUtil.CIPHER_ALGO_PROVIDER);
        keyStore.load(null, keystorePass.toCharArray());

        try (final FileOutputStream fos = new FileOutputStream(newStore)) {
            keyStore.store(fos, keystorePass.toCharArray());
        }


        // get secret key
        final SecretKey result = generateSecretKey();
        final URL keyFile = this.getClass().getClassLoader().getResource(CipherUtil.DEFAULT_KEYSTORE_NAME);


        // load keystore
        try (final InputStream stream =
                     //new FileInputStream(new File(keyFile.toURI()))) {
                     new FileInputStream(new File(CipherUtil.DEFAULT_KEYSTORE_NAME))) {
            keyStore.load(stream, keystorePass.toCharArray());
        };

        // create entry
        final KeyStore.SecretKeyEntry secret
                = new KeyStore.SecretKeyEntry(result);
        final KeyStore.ProtectionParameter password
                = new KeyStore.PasswordProtection(StringUtils.EMPTY.toCharArray());
        keyStore.setEntry(CipherUtil.KEYSECRET_ALIAS, secret, password);

        try (final FileOutputStream fos =new FileOutputStream(new File(CipherUtil.DEFAULT_KEYSTORE_NAME)) ) {
            keyStore.store(fos, keystorePass.toCharArray());
        }
    }
}