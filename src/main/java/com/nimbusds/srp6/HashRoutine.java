package com.nimbusds.srp6;


import java.security.MessageDigest;


/**
 * Interface for the principal hash 'H' routine.
 *
 * Used to compute the following SRP-6a values:
 *
 * <ul>
 *     <li>The multiplier 'k'.
 *     <li>The random scrambling parameter 'u'.
 *     <li>The client evidence message 'M1'.
 *     <li>The server evidence message 'M2'.
 * </ul>
 *
 * <p>The hash algorithm for the password key 'x' computation is set
 * independently.
 *
 * @author Vladimir Dzhuvinov
 */
public interface HashRoutine {


	/**
	 * Returns a {@link java.security.MessageDigest} instance for the hash
	 * routine.
	 *
	 * @return The message digest instance.
	 */
	public MessageDigest getMessageDigestInstance();


	/**
	 * Returns a one-way hash of the specified input.
	 *
	 * @param input The byte array to hash. Must not be {@code null}.
	 *
	 * @return The hash.
	 */
	public byte[] hash(final byte[] input);
}
