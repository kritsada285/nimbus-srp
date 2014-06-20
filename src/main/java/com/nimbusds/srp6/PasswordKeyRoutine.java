package com.nimbusds.srp6;


import java.math.BigInteger;


/**
 * Interface for computing the password key 'x'. Required by the
 * {@link com.nimbusds.srp6.SRP6VerifierGenerator verifier 'v' generator} and
 * by the authenticating {@link SRP6ClientSession client session}.
 *
 * <p>If you don't want to employ the
 * {@link com.nimbusds.srp6.DefaultRoutines#computeX default routine} for
 * computing 'x' you can use this interface to define your own. Make sure
 * exactly the same routine is used to generate the verifier 'v' and by client
 * authentication sessions later, else authentication will fail.
 *
 * <p>For another sample implementation see {@link com.nimbusds.srp6.alt.SHA1PasswordKeyRoutineWithUserIdentity}
 * which computes <code>x = H(s | H(I | ":" | P))</code>
 *
 * @author Vladimir Dzhuvinov
 */
public interface PasswordKeyRoutine {


	/**
	 * Computes the password key 'x'.
	 *
	 * <p>Tip: To convert a string to a byte array you can use
	 * {@code String.getBytes(java.nio.charset.Charset)}. To convert a big
	 * integer to a byte array you can use {@code BigInteger.toByteArray()}.
	 *
	 * @param salt     The salt 's'. This is considered a mandatory
	 *                 argument in the computation of 'x'.
	 * @param username The user identity 'I'. May be ignored if the
	 *                 username is allowed to change or if a user may 
	 *                 authenticate with multiple alternate identities,
	 *                 such as name and email address.
	 * @param password The user password 'P'. This is considered a
	 *                 mandatory argument in the computation of 'x'.
	 *
	 * @return The resulting 'x' value.
	 */
	public BigInteger computeX(final byte[] salt,
				   final byte[] username, 
				   final byte[] password);
}
