package com.nimbusds.srp6.js;

import static com.nimbusds.srp6.BigIntegerUtils.toHex;

import java.math.BigInteger;

import com.nimbusds.srp6.ClientEvidenceRoutine;
import com.nimbusds.srp6.SRP6ClientEvidenceContext;
import com.nimbusds.srp6.SRP6CryptoParams;

/**
 * Custom routine interface for computing the client evidence message 'M1'.
 * Compatible with browser implementations by using hashing of string
 * concatenated hex strings.
 * 
 * <p>
 * Specification RFC 2945
 * 
 * @author Simon Massey
 */
public class HexHashedClientEvidenceRoutine implements ClientEvidenceRoutine {

	/**
	 * Computes a client evidence message 'M1'.
	 * 
	 * @param cryptoParams
	 *            The crypto parameters for the SRP-6a protocol.
	 * @param ctx
	 *            Snapshot of the SRP-6a client session variables which may be
	 *            used in the computation of the client evidence message.
	 * 
	 * @return Client evidence message 'M1' as 'H( HEX(A) | HEX(B) | HEX(S) )'.
	 */
	@Override
	public BigInteger computeClientEvidence(SRP6CryptoParams cryptoParams, SRP6ClientEvidenceContext ctx) {
		return HexHashedRoutines.hashValues(cryptoParams.getMessageDigestInstance(), toHex(ctx.A), toHex(ctx.B), toHex(ctx.S));
	}
}
