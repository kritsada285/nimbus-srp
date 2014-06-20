package com.nimbusds.srp6;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.nimbusds.srp6.util.BigIntegerUtils;


/**
 * Default implementations of the SRP 'x', 'u', 'M1' and 'M2' routines.
 *
 * @author Vladimir Dzhuvinov
 */
public final class DefaultRoutines
	implements HashRoutine, PasswordKeyRoutine, URoutine, ClientEvidenceRoutine, ServerEvidenceRoutine {


	/**
	 * Singleton.
	 */
	private static final DefaultRoutines singleton = new DefaultRoutines();


	/**
	 * Prevents public instantiation.
	 */
	private DefaultRoutines() {

	}


	public static DefaultRoutines getInstance() {

		return singleton;
	}


	/**
	 * The hash algorithm 'H' (SHA-1) for the SRP routines.
	 */
	public static final String H = "SHA-1";


	@Override
	public MessageDigest getMessageDigestInstance() {

		try {
			return MessageDigest.getInstance(H);

		} catch (NoSuchAlgorithmException e) {

			return null;
		}
	}


	@Override
	public byte[] hash(final byte[] input) {

		return getMessageDigestInstance().digest(input);
	}

	@Override
	public BigInteger computeX(final byte[] salt,
				   final byte[] username,
				   final byte[] password) {

		MessageDigest digest = getMessageDigestInstance();

		byte[] output = digest.digest(password);

		digest.update(salt);
		digest.update(output);

		return new BigInteger(1, digest.digest());
	}


	/**
	 * Computes the random scrambling parameter
	 * <code>u = H(PAD(A) | PAD(B))</code>
	 *
	 * <p>Specification: RFC 5054.
	 */
	@Override
	public BigInteger computeU(final SRP6CryptoParams cryptoParams,
				   final URoutineContext ctx) {

		return BigIntegerUtils.hashPaddedPair(getMessageDigestInstance(), cryptoParams.N, ctx.A, ctx.B);
	}


	/**
	 * Computes the client evidence message <code>M1 = H(A | B | S)</code>
	 *
	 * <p>Specification: Tom Wu's paper "SRP-6: Improvements and
	 * refinements to the Secure Remote Password protocol", table 5, from
	 * 2002.
	 */
	@Override
	public BigInteger computeClientEvidence(final SRP6CryptoParams cryptoParams,
						final SRP6ClientEvidenceContext ctx) {

		MessageDigest digest = getMessageDigestInstance();

		digest.update(ctx.A.toByteArray());
		digest.update(ctx.B.toByteArray());
		digest.update(ctx.S.toByteArray());

		return new BigInteger(1, digest.digest());
	}


	/**
	 * Computes the server evidence message <code>M2 = H(A | M1 | S)</code>
	 *
	 * <p>Specification: Tom Wu's paper "SRP-6: Improvements and
	 * refinements to the Secure Remote Password protocol", table 5, from
	 * 2002.
	 */
	@Override
	public BigInteger computeServerEvidence(final SRP6CryptoParams cryptoParams,
						final SRP6ServerEvidenceContext ctx) {

		MessageDigest digest = getMessageDigestInstance();

		digest.update(ctx.A.toByteArray());
		digest.update(ctx.M1.toByteArray());
		digest.update(ctx.S.toByteArray());

		return new BigInteger(1, digest.digest());
	}
}
