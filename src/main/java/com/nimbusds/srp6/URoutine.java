package com.nimbusds.srp6;


import java.math.BigInteger;


/**
 * Interface for computing the random scrambling parameter
 * <code>u = H(A | B)</code>.
 * 
 * <p>If you don't want to employ the
 * {@link com.nimbusds.srp6.DefaultRoutines default routine} for computing 'u'
 * you can use this interface to define your own. Make sure exactly the same
 * routine is used by both client and server session, else authentication will
 * fail.
 * 
 * @author Simon Massey
 */
public interface URoutine {


	/**
	 * Computes the random scrambling parameter 'u'.
	 *
	 * @param cryptoParams The SRP-6a crypto parameters.
	 * @param ctx          Snapshot of the SRP-6a client session variables
	 *                     which may be used in the computation of the
	 *                     hashed keys message.
	 * 
	 * @return The resulting 'u' value'.
	 */
	public BigInteger computeU(final SRP6CryptoParams cryptoParams, final URoutineContext ctx);
}
