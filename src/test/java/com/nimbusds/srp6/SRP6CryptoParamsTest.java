package com.nimbusds.srp6;

import java.math.BigInteger;
import junit.framework.TestCase;

/**
 * Tests the SRP6 crypto params.
 */
public class SRP6CryptoParamsTest extends TestCase {

    private final byte[] password = "password".getBytes();

	public void testN256() {

        assertTrue(SRP6CryptoParams.N_256.isProbablePrime(15));

        SRP6VerifierGenerator generator = new SRP6VerifierGenerator(SRP6CryptoParams.getInstance(256, "SHA-512"));
        byte[] salt;
        for (int i = 0; i < 100; i++) {
            salt = generator.generateRandomSalt();
            assertEquals(16, salt.length);
            assertEquals(32, generator.generateVerifier(salt, password).toByteArray().length);
        }
    }

	public void testN512() {

        assertTrue(SRP6CryptoParams.N_512.isProbablePrime(15));

        SRP6VerifierGenerator generator = new SRP6VerifierGenerator(SRP6CryptoParams.getInstance(512, "SHA-512"));
        byte[] salt;
        for (int i = 0; i < 100; i++) {
            salt = generator.generateRandomSalt();
            assertEquals(16, salt.length);
            assertEquals(64, generator.generateVerifier(salt, password).toByteArray().length);
        }
    }

	public void testN768() {

        assertTrue(SRP6CryptoParams.N_768.isProbablePrime(15));

        SRP6VerifierGenerator generator = new SRP6VerifierGenerator(SRP6CryptoParams.getInstance(768, "SHA-512"));
        byte[] salt;
        for (int i = 0; i < 100; i++) {
            salt = generator.generateRandomSalt();
            assertEquals(16, salt.length);
            assertEquals(96, generator.generateVerifier(salt, password).toByteArray().length);
        }
    }

    public void testN1024() {

        assertTrue(SRP6CryptoParams.N_1024.isProbablePrime(15));

        SRP6VerifierGenerator generator = new SRP6VerifierGenerator(SRP6CryptoParams.getInstance(1024, "SHA-512"));
        byte[] salt;
        for (int i = 0; i < 100; i++) {
            salt = generator.generateRandomSalt();
            assertEquals(16, salt.length);
            assertEquals(128, generator.generateVerifier(salt, password).toByteArray().length);
        }
    }

	public void testN1536() {

        assertTrue(SRP6CryptoParams.N_1536.isProbablePrime(15));

        SRP6VerifierGenerator generator = new SRP6VerifierGenerator(SRP6CryptoParams.getInstance(1536, "SHA-512"));
        byte[] salt;
        for (int i = 0; i < 100; i++) {
            salt = generator.generateRandomSalt();
            assertEquals(16, salt.length);
            assertEquals(192, generator.generateVerifier(salt, password).toByteArray().length);
        }
    }

	public void testN2048() {

        assertTrue(SRP6CryptoParams.N_2048.isProbablePrime(15));

        SRP6VerifierGenerator generator = new SRP6VerifierGenerator(SRP6CryptoParams.getInstance(2048, "SHA-512"));
        byte[] salt;
        for (int i = 0; i < 100; i++) {
            salt = generator.generateRandomSalt();
            assertEquals(16, salt.length);
            assertEquals(256, generator.generateVerifier(salt, password).toByteArray().length);
        }
    }

    public void testN3072() {

        assertTrue(SRP6CryptoParams.N_3072.isProbablePrime(15));

        SRP6VerifierGenerator generator = new SRP6VerifierGenerator(SRP6CryptoParams.getInstance(3072, "SHA-512"));
        byte[] salt;
        for (int i = 0; i < 100; i++) {
            salt = generator.generateRandomSalt();
            assertEquals(16, salt.length);
            assertEquals(384, generator.generateVerifier(salt, password).toByteArray().length);
        }
    }

    public void testN4096() {

        assertTrue(SRP6CryptoParams.N_4096.isProbablePrime(15));

        SRP6VerifierGenerator generator = new SRP6VerifierGenerator(SRP6CryptoParams.getInstance(4096, "SHA-512"));
        byte[] salt;
        for (int i = 0; i < 100; i++) {
            salt = generator.generateRandomSalt();
            assertEquals(16, salt.length);
            assertEquals(512, generator.generateVerifier(salt, password).toByteArray().length);
        }
    }

	public void testN6144() {

        assertTrue(SRP6CryptoParams.N_6144.isProbablePrime(15));

        SRP6VerifierGenerator generator = new SRP6VerifierGenerator(SRP6CryptoParams.getInstance(6144, "SHA-512"));
        byte[] salt;
        for (int i = 0; i < 100; i++) {
            salt = generator.generateRandomSalt();
            assertEquals(16, salt.length);
            assertEquals(768, generator.generateVerifier(salt, password).toByteArray().length);
        }
    }

	public void testN8192() {

        assertTrue(SRP6CryptoParams.N_8192.isProbablePrime(15));

        SRP6VerifierGenerator generator = new SRP6VerifierGenerator(SRP6CryptoParams.getInstance(8192, "SHA-512"));
        byte[] salt;
        for (int i = 0; i < 100; i++) {
            salt = generator.generateRandomSalt();
            assertEquals(16, salt.length);
            assertEquals(1024, generator.generateVerifier(salt, password).toByteArray().length);
        }
    }

	public void testIllegalGeneratorArg() {

		try {
			new SRP6CryptoParams(SRP6CryptoParams.N_256, null, "SHA-1");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The generator parameter 'g' must not be null", e.getMessage());
		}

		try {
			new SRP6CryptoParams(SRP6CryptoParams.N_256, BigInteger.ONE, "SHA-1");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The generator parameter 'g' must not be 1", e.getMessage());
		}

		try {
			new SRP6CryptoParams(SRP6CryptoParams.N_256, SRP6CryptoParams.N_256.subtract(BigInteger.ONE), "SHA-1");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The generator parameter 'g' must not equal N - 1", e.getMessage());
		}

		try {
			new SRP6CryptoParams(SRP6CryptoParams.N_256, BigInteger.ZERO, "SHA-1");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The generator parameter 'g' must not be 0", e.getMessage());
		}
	}
}
