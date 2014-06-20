package com.nimbusds.srp6;


import java.math.BigInteger;

import junit.framework.TestCase;


/**
 * Tests the SRP-6a crypto parameters class.
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6CryptoParamsTest extends TestCase {


	public void testPrecomputedPrimes() {

		assertTrue(SRP6CryptoParams.N_256.isProbablePrime(1));
		assertTrue(SRP6CryptoParams.N_512.isProbablePrime(1));
		assertTrue(SRP6CryptoParams.N_768.isProbablePrime(1));
		assertTrue(SRP6CryptoParams.N_1024.isProbablePrime(1));
	}


	public void testGetInstance() {

		assertEquals(SRP6CryptoParams.N_512, SRP6CryptoParams.getInstance().N);
		assertEquals(SRP6CryptoParams.g_common, SRP6CryptoParams.getInstance().g);

		assertEquals(SRP6CryptoParams.N_256, SRP6CryptoParams.getInstance(256).N);
		assertEquals(SRP6CryptoParams.g_common, SRP6CryptoParams.getInstance(256).g);

		assertEquals(SRP6CryptoParams.N_512, SRP6CryptoParams.getInstance(512).N);
		assertEquals(SRP6CryptoParams.g_common, SRP6CryptoParams.getInstance(512).g);

		assertEquals(SRP6CryptoParams.N_768, SRP6CryptoParams.getInstance(768).N);
		assertEquals(SRP6CryptoParams.g_common, SRP6CryptoParams.getInstance(768).g);

		assertEquals(SRP6CryptoParams.N_1024, SRP6CryptoParams.getInstance(1024).N);
		assertEquals(SRP6CryptoParams.g_common, SRP6CryptoParams.getInstance(1024).g);

		assertNull(SRP6CryptoParams.getInstance(2048));
	}


	public void testConstructor() {

		BigInteger N = new BigInteger("7");
		BigInteger g = new BigInteger("2");

		SRP6CryptoParams cryptoParams = new SRP6CryptoParams(N, g);
		assertEquals(N, cryptoParams.N);
		assertEquals(g, cryptoParams.g);
	}
}
