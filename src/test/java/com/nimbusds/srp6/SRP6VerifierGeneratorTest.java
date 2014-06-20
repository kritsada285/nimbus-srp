package com.nimbusds.srp6;


import java.math.BigInteger;
import java.nio.charset.Charset;


import junit.framework.*;


/**
 * Tests the SRP-6a verifier generator.
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6VerifierGeneratorTest extends TestCase {
	
	
	public void testConstructors()
		throws Exception {
	
		SRP6CryptoParams config = SRP6CryptoParams.getInstance();
		
		SRP6VerifierGenerator gen = new SRP6VerifierGenerator(config);
		
		final byte[] salt = SRP6VerifierGenerator.generateRandomSalt();
		final byte[] uid = "alice".getBytes(Charset.forName("UTF-8"));
		final byte[] password = "secret".getBytes(Charset.forName("UTF-8"));
		
		BigInteger targetV = SRP6Routines.computeVerifier(
			config.N,
			config.g,
			DefaultRoutines.getInstance().computeX(
				salt,
				uid,
				password));

		assertEquals(targetV, gen.generateVerifier(salt, password));
		assertEquals(targetV, gen.generateVerifier(salt, uid, password));
	}
}
