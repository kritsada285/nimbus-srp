package com.nimbusds.srp6;


import java.math.BigInteger;
import java.security.MessageDigest;


/**
 * Alternative routine for computing a password key
 * <code>x = H(s | H(I | ":" | P))</code> where 'H' is
 * {@link com.nimbusds.srp6.DefaultRoutines#H SHA-1}.
 * 
 * <p>Specification: RFC 5054.
 *
 * <p>This routine can be passed to the {@link SRP6VerifierGenerator} and
 * {@link SRP6ClientSession} to replace the
 * {@link com.nimbusds.srp6.DefaultRoutines#computeX default routine}
 * <code>x = H(s | H(P))</code>.
 *
 * @author Vladimir Dzhuvinov
 */
public class SHA1PasswordKeyRoutineWithUserIdentity implements PasswordKeyRoutine {


	@Override
	public BigInteger computeX(final byte[] salt,
				   final byte[] username,
				   final byte[] password) {

		MessageDigest digest = DefaultRoutines.getInstance().getMessageDigestInstance();

		digest.update(username);
		digest.update((byte)':');
		digest.update(password);
		
		byte[] output = digest.digest();
		
		digest.update(salt);
		output = digest.digest(output);

		return new BigInteger(1, output);
	}
}
