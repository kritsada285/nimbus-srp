package com.nimbusds.srp6;


import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;


/**
 * Generator of password verifier 'v' values.
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6VerifierGenerator {


	/**
	 * The crypto parameters.
	 */
	private final SRP6CryptoParams cryptoParams;
	
	
	/**
	 * The password key 'x' routine.
	 */
	private PasswordKeyRoutine xRoutine = DefaultRoutines.getInstance();
	
	
	/**
	 * Creates a new generator of password verifier 'v' values.
	 *
	 * @param cryptoParams The SRP-6a crypto parameters. Must not be
	 *                     {@code null}.
	 */
	public SRP6VerifierGenerator(final SRP6CryptoParams cryptoParams) {
	
		if (cryptoParams == null)
			throw new IllegalArgumentException("The SRP-6a crypto parameters must not be null");
		
		this.cryptoParams = cryptoParams;
	}
	
	
	/**
	 * Generates a random salt 's'.
	 *
	 * @param numBytes The number of bytes the salt 's' must have.
	 *
	 * @return The salt 's' as a byte array.
	 */
	public static byte[] generateRandomSalt(final int numBytes) {

		byte[] salt = new byte[numBytes];
		new SecureRandom().nextBytes(salt);
		return salt;
	}
	
	
	/**
	 * Generates a random 16-byte salt 's'.
	 *
	 * @return The salt 's' as a byte array.
	 */
	public static byte[] generateRandomSalt() {
	
		return generateRandomSalt(16);
	}
	
	
	/**
	 * Sets the routine for the password key 'x' computation.
	 *
	 * @param XRoutine The password key 'x' routine. Must not be
	 *                 {@code null}.
	 */
	public void setPasswordKeyRoutine(final PasswordKeyRoutine XRoutine) {

		if (xRoutine == null)
			throw new IllegalArgumentException("The password key 'x' routine must not be null");
	
		xRoutine = XRoutine;
	}
	
	
	/**
	 * Gets the routine for the password key 'x' computation.
	 *
	 * @return The password key 'x' routine.
	 */
	public PasswordKeyRoutine getPasswordKeyRoutine() {
	
		return xRoutine;
	}
	
	
	/**
	 * Generates a new verifier 'v' from the specified parameters.
	 *
	 * <p>The verifier is computed as <code>v = g^x (mod N)</code>.
	 *
	 * <p>Tip: To convert a string to a byte array you can use
	 * {@code String.getBytes(java.nio.charset.Charset)}. To convert a big
	 * integer to a byte array you can use {@code BigInteger.toByteArray()}.
	 *
	 * @param salt     The salt 's'. Must not be {@code null}.
	 * @param userID   The user identity 'I'. May be {@code null} if the
	 *                 default 'x' routine is used or the custom one
	 *                 ignores it.
	 * @param password The user password 'P'. Must not be {@code null}. 
	 *
	 * @return The resulting verifier 'v'.
	 */
	public BigInteger generateVerifier(final byte[] salt, final byte[] userID, final byte[] password) {
	
		if (salt == null)
			throw new IllegalArgumentException("The salt 's' must not be null");
		
		if (password == null)
			throw new IllegalArgumentException("The password 'P' must not be null");
	
		// Compute the password key 'x'
		BigInteger x = xRoutine.computeX(
			salt,
			userID,
			password);
		
		return SRP6Routines.computeVerifier(cryptoParams.N, cryptoParams.g, x);
	}
	
	
	/**
	 * Generates a new verifier 'v' from the specified parameters.
	 *
	 * <p>The verifier is computed as <code>v = g^x (mod N)</code>.
	 *
	 * @param salt     The salt 's'. Must not be {@code null}.
	 * @param userID   The user identity 'I', as an UTF-8 encoded string. 
	 *                 May be {@code null} if the default 'x' routine is 
	 *                 used or the custom one ignores it.
	 * @param password The user password 'P', as an UTF-8 encoded string. 
	 *                 Must not be {@code null}. 
	 *
	 * @return The resulting verifier 'v'.
	 */
	public BigInteger generateVerifier(final BigInteger salt, final String userID, final String password) {
	
		byte[] userIDBytes = null;
		
		if (userID != null)
			userIDBytes = userID.getBytes(Charset.forName("UTF-8"));
		
		return generateVerifier(salt.toByteArray(), userIDBytes, password.getBytes(Charset.forName("UTF-8")));
	}
	
	
	/**
	 * Generates a new verifier 'v' from the specified parameters with the
	 * user identifier 'I' omitted.
	 *
	 * <p>The verifier is computed as <code>v = g^x (mod N)</code>.
	 *
	 * <p>If a custom {@link #setPasswordKeyRoutine 'x' computation routine} is set
	 * it must omit the user identity 'I' as well.
	 *
	 * <p>Tip: To convert a string to a byte array you can use
	 * {@code String.getBytes(java.nio.charset.Charset)}. To convert a big
	 * integer to a byte array you can use {@code BigInteger.toByteArray()}.
	 *
	 * @param salt     The salt 's'. Must not be {@code null}.
	 * @param password The user password 'P'. Must not be {@code null}. 
	 *
	 * @return The resulting verifier 'v'.
	 */
	public BigInteger generateVerifier(final byte[] salt, final byte[] password) {
	
		return generateVerifier(salt, null, password);
	}
	
	
	/**
	 * Generates a new verifier 'v' from the specified parameters with the
	 * user identifier 'I' omitted.
	 *
	 * <p>The verifier is computed as <code>v = g^x (mod N)</code>.
	 *
	 * <p>If a custom {@link #setPasswordKeyRoutine 'x' computation routine} is set
	 * it must omit the user identity 'I' as well.
	 *
	 * @param salt     The salt 's'. Must not be {@code null}.
	 * @param password The user password 'P', as an UTF-8 encoded string. 
	 *                 Must not be {@code null}. 
	 *
	 * @return The resulting verifier 'v'.
	 */
	public BigInteger generateVerifier(final BigInteger salt, final String password) {
	
		return generateVerifier(salt, null, password);
	}
}
