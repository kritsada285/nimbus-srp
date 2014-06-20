package com.nimbusds.srp6.util;


import java.math.BigInteger;

import junit.framework.TestCase;


/**
 * Tests the BigInteger utility class.
 *
 * @author Vladimir Dzhuvinov
 */
public class BigIntegerUtilsTest extends TestCase {


	public void testRoundTripHexConversion() {

		BigInteger bigInteger = new BigInteger("1234567890");

		String hex = BigIntegerUtils.toHex(bigInteger);

		assertTrue(bigInteger.equals(BigIntegerUtils.fromHex(hex)));
	}
}
