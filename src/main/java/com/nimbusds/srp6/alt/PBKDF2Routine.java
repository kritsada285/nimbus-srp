package com.nimbusds.srp6.alt;


import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.nimbusds.srp6.PasswordKeyRoutine;


/**
 * Alternative routine for computing a password key
 * <code>x = H(s | P))</code> where 'H' is PBKDF2.
 *
 * <p>Specification: RFC 2898.
 *
 * <p>This routine can be passed to the
 * {@link com.nimbusds.srp6.SRP6VerifierGenerator} and
 * {@link com.nimbusds.srp6.SRP6ClientSession} to replace the
 * {@link com.nimbusds.srp6.DefaultRoutines#computeX default routine}
 * <code>x = H(s | H(P))</code>.
 *
 * @author Vladimir Dzhuvinov
 */
public class PBKDF2Routine implements PasswordKeyRoutine {


	@Override
	public BigInteger computeX(byte[] salt, byte[] username, byte[] password) {

		// PBKDF2 with SHA-1 as the hashing algorithm. Note that the NIST
		// specifically names SHA-1 as an acceptable hashing algorithm for PBKDF2
		final String algorithm = "PBKDF2WithHmacSHA1";

		// SHA-1 generates 160 bit hashes, so that's what makes sense here
		int derivedKeyLength = 160;
		// Pick an iteration count that works for you. The NIST recommends at
		// least 1,000 iterations:
		int iterations = 20000;

		KeySpec spec = new PBEKeySpec(
			new String(password, Charset.forName("UTF-8")).toCharArray(),
			salt,
			iterations,
			derivedKeyLength);


		SecretKeyFactory f;

		try {
			f = SecretKeyFactory.getInstance(algorithm);

		} catch (NoSuchAlgorithmException e) {
			return null;
		}

		byte[] key;

		try {
			key = f.generateSecret(spec).getEncoded();
		} catch (InvalidKeySpecException e) {

			return null;
		}

		return new BigInteger(1, key);
	}
}
