package com.nimbusds.srp6.alt;


import java.math.BigInteger;

import com.nimbusds.srp6.PasswordKeyRoutine;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6VerifierGenerator;
import com.nimbusds.srp6.util.BigIntegerUtils;

import junit.framework.TestCase;


/**
 * Test the alternative 'x' routine.
 *
 * @author Vladimir Dzhuvinov
 */
public class SHA1PasswordKeyRoutineWithUserIdentityTest extends TestCase {
	
	
	public void test() {
	
		// Use http://srp.stanford.edu/demo/demo.html as benchmark and
		// for test vectors
		BigInteger N = BigIntegerUtils.fromHex("115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3");
		BigInteger g = BigIntegerUtils.fromHex("2");
		
		SRP6CryptoParams config = new SRP6CryptoParams(N, g);
		
		// Credentials
		final BigInteger salt = BigIntegerUtils.fromHex("1e97da52cbdcd653f85b");
		final String userID = "alice";
		final String password = "secret";
		
		// Create verifier and set alt routine x = H(s | H(I | ":" | P))
		
		SRP6VerifierGenerator gen = new SRP6VerifierGenerator(config);
		assertNotNull(gen.getPasswordKeyRoutine());
		
		PasswordKeyRoutine altX = new SHA1PasswordKeyRoutineWithUserIdentity();
		gen.setPasswordKeyRoutine(altX);
		assertEquals(altX, gen.getPasswordKeyRoutine());
		
		BigInteger v = gen.generateVerifier(salt, userID, password);
		
		// From demo
		BigInteger targetV = BigIntegerUtils.fromHex("100e0c40a5c281dbfb046911634f8e69d3469964863c01eb4683d8d182926da72");
		
		assertEquals(targetV, v);
	}
}
