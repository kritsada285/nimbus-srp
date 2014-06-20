package com.nimbusds.srp6;


import java.math.BigInteger;


/**
 * Interface for computing the server evidence message 'M2'.
 *
 * <p>If you don't want to employ the
 * {@link com.nimbusds.srp6.DefaultRoutines#computeServerEvidence default
 * routine} for computing the server evidence message you can use this
 * interface to define your own. Make sure exactly the same routine is used by
 * both client and server session, else authentication will fail.
 *
 * @author Vladimir Dzhuvinov
 */
public interface ServerEvidenceRoutine {


	/**
	 * Computes a server evidence message 'M2'.
	 *
	 * @param cryptoParams The SRP-6a crypto parameters.
	 * @param ctx          Snapshot of the SRP-6a server session variables 
	 *                     which may be used in the computation of the 
	 *                     server evidence message.
	 *
	 * @return The resulting server evidence message 'M1'.
	 */
	public BigInteger computeServerEvidence(final SRP6CryptoParams cryptoParams,
	                                        final SRP6ServerEvidenceContext ctx);
}
