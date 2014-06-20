package com.nimbusds.srp6;


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
}
