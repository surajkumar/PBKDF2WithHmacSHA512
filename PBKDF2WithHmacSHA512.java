import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * <p>
 * This class is used for encrypting passwords using the PBKDF2WithHmacSHA1
 * algorithm. Passwords are salted using SHA1PRNG.
 * </p>
 * <p>
 * <a href=
 * "http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf"
 * >Specification referenced</a>.<br>
 * <a href="http://tools.ietf.org/search/rfc2898">RFC2898 - Password-Based
 * Cryptography Specification</a>
 *
 * @author Suraj Kumar
 * @version 1.0
 */
public final class PBKDF2WithHmacSHA512 {
    /**
     * This is the algorithm this service uses.
     */
    private static final String ALGORITHM = PBKDF2WithHmacSHA512.class.getSimpleName();

    /**
     * The amount of computation needed to derive a key from the password. Note:
     * The bigger the number the longer it'll take to a generate key. Note: When
     * user based performance is not an issue, a value of 10,000,000 is
     * recommended otherwise a minimum of 1000 recommended.
     */
    private static final int ITERATION_COUNT = 1000;

    /**
     * The length of the derived key.
     */
    private static final int KEY_LENGTH = 64;

    /**
     * Private constructor to stop the class from being instantiated.
     *
     * @throws AssertionError If the class tried to be instantiated.
     */
    private PBKDF2WithHmacSHA512() {
        throw new AssertionError();
    }

    /**
     * This method returns an encrypted byte[] of the password.
     *
     * @param password The password to encrypt.
     * @param salt     The random data used for the hashing function.
     * @return The encrypted password as a byte[].
     * @throws NoSuchAlgorithmException If the cryptographic algorithm is unavailable.
     * @throws InvalidKeySpecException  If the derived key cannot be produced.
     */
    public static byte[] hash(final String password, final byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        final SecretKeyFactory secretKeyfactory = SecretKeyFactory.getInstance(ALGORITHM);
        return secretKeyfactory.generateSecret(keySpec).getEncoded();
    }

    /**
     * Generates a random salt used for password matching.
     *
     * @return A randomly produced byte[].
     * @throws NoSuchAlgorithmException If SHA1PRNG does not exist on the system.
     */
    public static byte[] salt() throws NoSuchAlgorithmException {
        final byte[] salt = new byte[16];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(salt);
        return salt;
    }

    /**
     * Checks the attemptedPassword against the encryptedPassword using the
     * random salt.
     *
     * @param attemptedPassword The password entered by the user.
     * @param hashedPassword    The hashed password stored on the database.
     * @param salt              The salt to use
     * @return True, if the attempted password matched the hashed password.
     * @throws Exception If the algorithm cannot be performed.
     */
    public static boolean authenticate(final String attemptedPassword, final byte[] salt, final byte[] hashedPassword) throws Exception {
        return Arrays.equals(hash(attemptedPassword, salt), hashedPassword);
    }
}
