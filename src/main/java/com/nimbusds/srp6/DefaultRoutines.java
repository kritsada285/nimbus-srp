package com.nimbusds.srp6;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * Default implementations of the SRP 'x', 'u', 'M1' and 'M2' routines.
 *
 * @author Vladimir Dzhuvinov
 */
public class DefaultRoutines
	implements XRoutine, URoutine, ClientEvidenceRoutine, ServerEvidenceRoutine {


	/**
	 * Singleton.
	 */
	private static DefaultRoutines singleton = new DefaultRoutines();


	/**
	 * Prevents public instantiation.
	 */
	private DefaultRoutines() {

	}


	public static DefaultRoutines getInstance() {

		return singleton;
	}


	private MessageDigest newMessageDigest() {

		try {
			return MessageDigest.getInstance("SHA-1");

		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}


	@Override
	public BigInteger computeX(final MessageDigest digest,
				   final byte[] salt,
				   final byte[] username,
				   final byte[] password) {

		byte[] output = digest.digest(password);

		digest.update(salt);
		digest.update(output);

		return new BigInteger(1, digest.digest());
	}


	@Override
	public BigInteger computeU(final SRP6CryptoParams cryptoParams,
				   final URoutineContext ctx) {

		return BigIntegerUtils.hashPaddedPair(newMessageDigest(), cryptoParams.N, ctx.A, ctx.B);
	}


	@Override
	public BigInteger computeClientEvidence(final SRP6CryptoParams cryptoParams,
						final SRP6ClientEvidenceContext ctx) {

		MessageDigest digest = newMessageDigest();

		digest.update(ctx.A.toByteArray());
		digest.update(ctx.B.toByteArray());
		digest.update(ctx.S.toByteArray());

		return new BigInteger(1, digest.digest());
	}


	@Override
	public BigInteger computeServerEvidence(final SRP6CryptoParams cryptoParams,
						final SRP6ServerEvidenceContext ctx) {

		MessageDigest digest = newMessageDigest();

		digest.update(ctx.A.toByteArray());
		digest.update(ctx.M1.toByteArray());
		digest.update(ctx.S.toByteArray());

		return new BigInteger(1, digest.digest());
	}
}
