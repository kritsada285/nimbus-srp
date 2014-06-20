package com.nimbusds.srp6.alt;


import java.math.BigInteger;
import java.nio.charset.Charset;

import com.nimbusds.srp6.*;

import junit.framework.TestCase;


/**
 * Test the PBKDF2-based 'x' routine.
 *
 * @author Vladimir Dzhuvinov
 */
public class PBKDF2RoutineTest extends TestCase {


	public void testDefaultIterationCount() {

		assertEquals(20000, PBKDF2Routine.DEFAULT_ITERATION_COUNT);
	}
	
	
	public void testDefault() {

		// username + password
		final String username = "alice";
		final String password = "secret";
	
		SRP6CryptoParams cryptoParams = SRP6CryptoParams.getInstance();

		SRP6VerifierGenerator gen = new SRP6VerifierGenerator(cryptoParams);
		PasswordKeyRoutine xRoutine = new PBKDF2Routine();
		gen.setPasswordKeyRoutine(xRoutine);
		assertEquals(xRoutine, gen.getPasswordKeyRoutine());

		final byte[] salt = SRP6VerifierGenerator.generateRandomSalt();

		BigInteger v = gen.generateVerifier(salt, username.getBytes(Charset.forName("UTF-8")), password.getBytes(Charset.forName("UTF-8")));

		// Init client and server
		SRP6ClientSession client = new SRP6ClientSession();
		client.setPasswordKeyRoutine(xRoutine);

		SRP6ServerSession server = new SRP6ServerSession(cryptoParams);

		// Step ONE
		client.step1(username, password);
		BigInteger B = server.step1(username, new BigInteger(1, salt), v);

		// Step TWO

		SRP6ClientCredentials cred = null;

		try {
			cred = client.step2(cryptoParams, new BigInteger(1, salt), B);

		} catch (SRP6Exception e) {
			fail("Client step 2 failed: " + e.getMessage());
		}

		BigInteger M2 = null;

		try {
			M2 = server.step2(cred.A, cred.M1);

		} catch (SRP6Exception e) {

			fail("Server step 2 failed: " + e.getMessage());
		}


		// Step THREE

		try {
			client.step3(M2);

		} catch (SRP6Exception e) {
			fail("Client step 3 failed: " + e.getMessage());
		}
	}


	public void testWithSpecificIterationCount() {

		// username + password
		final String username = "alice";
		final String password = "secret";

		SRP6CryptoParams cryptoParams = SRP6CryptoParams.getInstance();

		SRP6VerifierGenerator gen = new SRP6VerifierGenerator(cryptoParams);

		final int iterations = 10000;
		PBKDF2Routine xRoutine = new PBKDF2Routine(iterations);
		assertEquals(iterations, xRoutine.getIterations());

		gen.setPasswordKeyRoutine(xRoutine);
		assertEquals(xRoutine, gen.getPasswordKeyRoutine());

		final byte[] salt = SRP6VerifierGenerator.generateRandomSalt();

		BigInteger v = gen.generateVerifier(salt, username.getBytes(Charset.forName("UTF-8")), password.getBytes(Charset.forName("UTF-8")));

		// Init client and server
		SRP6ClientSession client = new SRP6ClientSession();
		client.setPasswordKeyRoutine(xRoutine);

		SRP6ServerSession server = new SRP6ServerSession(cryptoParams);

		// Step ONE
		client.step1(username, password);
		BigInteger B = server.step1(username, new BigInteger(1, salt), v);

		// Step TWO

		SRP6ClientCredentials cred = null;

		try {
			cred = client.step2(cryptoParams, new BigInteger(1, salt), B);

		} catch (SRP6Exception e) {
			fail("Client step 2 failed: " + e.getMessage());
		}

		BigInteger M2 = null;

		try {
			M2 = server.step2(cred.A, cred.M1);

		} catch (SRP6Exception e) {

			fail("Server step 2 failed: " + e.getMessage());
		}


		// Step THREE

		try {
			client.step3(M2);

		} catch (SRP6Exception e) {
			fail("Client step 3 failed: " + e.getMessage());
		}
	}
}
