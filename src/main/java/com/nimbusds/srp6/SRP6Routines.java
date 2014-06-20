package com.nimbusds.srp6;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import com.nimbusds.srp6.util.BigIntegerUtils;


/**
 * Secure Remote Password (SRP-6a) routines for computing / generating the
 * principal cryptographic variables and protocol messages.
 *
 * <p>The routines comply with RFC 5054 (SRP for TLS).
 *
 * <p>This class contains code from Bouncy Castle's SRP6 implementation.
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6Routines {

	
	/**
	 * Computes the SRP-6 multiplier <code>k = H(N | PAD(g))</code>
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param digest The hash function 'H'. Must not be {@code null}.
	 * @param N      The prime parameter 'N'. Must not be {@code null}.
	 * @param g      The generator parameter 'g'. Must not be {@code null}.
	 *
	 * @return The resulting multiplier 'k'.
	 */
	public static BigInteger computeK(final MessageDigest digest, 
	                                  final BigInteger N, 
	                                  final BigInteger g) {
	
		return BigIntegerUtils.hashPaddedPair(digest, N, N, g);
	}
	
	
	/**
	 * Computes a verifier <code>v = g^x (mod N)</code>
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param N The prime parameter 'N'. Must not be {@code null}.
	 * @param g The generator parameter 'g'. Must not be {@code null}.
	 * @param x The password key 'x'. Must not be {@code null}.
	 *
	 * @return The resulting verifier 'v'.
	 */
	public static BigInteger computeVerifier(final BigInteger N,
	                                         final BigInteger g,
	                                         final BigInteger x) {
	
		return g.modPow(x, N);
	}                  
	
	
	/**
	 * Generates a random SRP-6a client or server private value ('a' or 
	 * 'b') which is 256 bits long.
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param N      The prime parameter 'N'. Must not be {@code null}.
	 * @param random Source of randomness. Must not be {@code null}.
	 *
	 * @return The resulting client or server private value ('a' or 'b').
	 */
	public static BigInteger generatePrivateValue(final BigInteger N,
	                                              final SecureRandom random) {
	 
		final int minBits = Math.min(256, N.bitLength() / 2);
		
		BigInteger min = BigInteger.ONE.shiftLeft(minBits - 1);
		BigInteger max = N.subtract(BigInteger.ONE);
		
		return BigIntegerUtils.createRandomInRange(min, max, random);
	}
	
	
	/**
	 * Computes the public client value <code>A = g^a (mod N)</code>
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param N The prime parameter 'N'. Must not be {@code null}.
	 * @param g The generator parameter 'g'. Must not be {@code null}.
	 * @param a The private client value 'a'. Must not be {@code null}.
	 *
	 * @return The public client value 'A'.
	 */
	public static BigInteger computePublicClientValue(final BigInteger N,
	                                                  final BigInteger g,
	                                                  final BigInteger a) {
	                                                    
		return g.modPow(a, N);
	}
	
	
	
	/**
	 * Computes the public server value
	 * <code>B = k * v + g^b (mod N)</code>
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param N The prime parameter 'N'. Must not be {@code null}.
	 * @param g The generator parameter 'g'. Must not be {@code null}.
	 * @param k The SRP-6a multiplier 'k'. Must not be {@code null}.
	 * @param v The password verifier 'v'. Must not be {@code null}.
	 * @param b The private server value 'b'. Must not be {@code null}.
	 *
	 * @return The public server value 'B'.
	 */
	public static BigInteger computePublicServerValue(final BigInteger N,
	                                                  final BigInteger g,
	                                                  final BigInteger k,
	                                                  final BigInteger v,
	                                                  final BigInteger b) {
	
		// Original from Bouncy Castle, modified:
		// return k.multiply(v).add(g.modPow(b, N));
		
		// Below from http://srp.stanford.edu/demo/demo.html
		return g.modPow(b, N).add(v.multiply(k)).mod(N);
	}
	
	
	/**
	 * Validates an SRP6 client or server public value ('A' or 'B').
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param N     The prime parameter 'N'. Must not be {@code null}.
	 * @param value The public value ('A' or 'B') to validate.
	 *
	 * @return {@code true} on successful validation, else {@code false}.
	 */
	public static boolean isValidPublicValue(final BigInteger N,
	                                         final BigInteger value) {
		
		// check that value % N != 0
		return !value.mod(N).equals(BigInteger.ZERO);
	}
	
	
	/**
	 * Computes the session key
	 * <code>S = (B - k * g^x) ^ (a + u * x) (mod N)</code> from
	 * client-side parameters.
	 * 
	 * <p>Specification: RFC 5054
	 *
	 * @param N The prime parameter 'N'. Must not be {@code null}.
	 * @param g The generator parameter 'g'. Must not be {@code null}.
	 * @param k The SRP-6a multiplier 'k'. Must not be {@code null}.
	 * @param x The 'x' value. Must not be {@code null}.
	 * @param u The random scrambling parameter 'u'. Must not be 
	 *          {@code null}.
	 * @param a The private client value 'a'. Must not be {@code null}.
	 * @param B The public server value 'B'. Must note be {@code null}.
	 *
	 * @return The resulting session key 'S'.
	 */
	public static BigInteger computeSessionKey(final BigInteger N,
	                                           final BigInteger g,
	                                           final BigInteger k,
	                                           final BigInteger x,
	                                           final BigInteger u,
	                                           final BigInteger a,
	                                           final BigInteger B) {
		
		final BigInteger exp = u.multiply(x).add(a);
		final BigInteger tmp = g.modPow(x, N).multiply(k);
		return B.subtract(tmp).modPow(exp, N);
	}
	
	
	/**
	 * Computes the session key <code>S = (A * v^u) ^ b (mod N)</code> from
	 * server-side parameters.
	 *
	 * <p>Specification: RFC 5054
	 *
	 * @param N The prime parameter 'N'. Must not be {@code null}.
	 * @param v The password verifier 'v'. Must not be {@code null}.
	 * @param u The random scrambling parameter 'u'. Must not be 
	 *          {@code null}.
	 * @param A The public client value 'A'. Must not be {@code null}.
	 * @param b The private server value 'b'. Must not be {@code null}.
	 *
	 * @return The resulting session key 'S'.
	 */
	public static BigInteger computeSessionKey(final BigInteger N,
	                                           final BigInteger v,
	                                           final BigInteger u,
	                                           final BigInteger A,
	                                           final BigInteger b) {
	
		return v.modPow(u, N).multiply(A).modPow(b, N);
	}


	/**
	 * Prevents public instantiation.
	 */
	private SRP6Routines() {
		// empty
	}
}
