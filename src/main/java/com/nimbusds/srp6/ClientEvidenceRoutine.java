package com.nimbusds.srp6;


import java.math.BigInteger;


/**
 * Interface for computing the client evidence message 'M1'.
 *
 * <p>If you don't want to employ the
 * {@link com.nimbusds.srp6.DefaultRoutines#computeClientEvidence default
 * routine} for computing the client evidence message you can use this
 * interface to define your own. Make sure exactly the same routine is used by
 * both client and server session, else authentication will fail.
 *
 * @author Vladimir Dzhuvinov
 */
public interface ClientEvidenceRoutine {


	/**
	 * Computes a client evidence message 'M1'.
	 *
	 * @param cryptoParams The SRP-6a crypto parameters.
	 * @param ctx          Snapshot of the SRP-6a client session variables 
	 *                     which may be used in the computation of the 
	 *                     client evidence message.
	 *
	 * @return The resulting client evidence message 'M1'.
	 */
	public BigInteger computeClientEvidence(final SRP6CryptoParams cryptoParams,
	                                        final SRP6ClientEvidenceContext ctx);

}
