package com.nimbusds.srp6;


import java.math.BigInteger;
import java.security.MessageDigest;


/**
 * Big integer utilities.
 *
 * <p>Contain source code portions from Apache Xerces and Aduna Software on
 * java2s.com.
 *
 * @author Vladimir Dzhuvinov
 * @author John Kim
 * @author others
 */
public class BigIntegerUtils {


	/**
	 * Encodes the specified big integer into a hex string.
	 *
	 * @param bigInteger The big integer. May be {@code null}.
	 *
	 * @return The resulting hex encoded string, or {@code null} if the
	 *         input is undefined.
	 */
	public static String toHex(final BigInteger bigInteger) {

		if (bigInteger == null)
			return null;

		return bigInteger.toString(16);
	}


	/**
	 * Decodes the specified hex string into a big integer.
	 *
	 * @param hex The hex string. May be {@code null}.
	 *
	 * @return The resulting big integer, or {@code null} if the input is
	 *         undefined or decoding failed.
	 */
	public static BigInteger fromHex(final String hex) {

		if (hex == null)
			return null;

		try {
			return new BigInteger(hex, 16);

		} catch (NumberFormatException e) {

			return null;
		}
	}


	/**
	 * Returns the specified big integer as an unsigned byte array.
	 *
	 * @param bigInteger The big integer. Must not be {@code null}.
	 *
	 * @return The byte array, without a leading zero if present in the
	 *         signed encoding.
	 */
	public static byte[] toUnsignedByteArray(final BigInteger bigInteger) {

		byte[] bytes = bigInteger.toByteArray();

		// remove leading zero if any
		if (bytes[0] == 0) {

			byte[] tmp = new byte[bytes.length - 1];

			System.arraycopy(bytes, 1, tmp, 0, tmp.length);

			return tmp;
		}

		return bytes;
	}


	/**
	 * Returns the specified big integer as a padded unsigned byte array.
	 *
	 * @param bigInteger The big integer. Must not be {@code null}.
	 * @param length     The required length of the padded byte array.
	 *
	 * @return The padded byte array.
	 */
	public static byte[] toUnsignedPaddedByteArray(final BigInteger bigInteger,
							  final int length) {

		byte[] bs = toUnsignedByteArray(bigInteger);

		if (bs.length < length) {

			byte[] tmp = new byte[length];
			System.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
			bs = tmp;
		}

		return bs;
	}


	/**
	 * Hashes two padded big integers 'n1' and 'n2' where the total length
	 * is determined by the size of N.
	 *
	 * <p>H(PAD(n1) | PAD(n2))
	 *
	 * @param digest The hash function 'H'. Must not be {@code null}.
	 * @param N      Its size determines the pad length. Must not be
	 *               {@code null}.
	 * @param n1     The first big integer to pad and hash. Must not be
	 *               {@code null}.
	 * @param n2     The second big integer to pad and hash. Must not be
	 *               {@code null}.
	 *
	 * @return The resulting hashed padded pair.
	 */
	protected static BigInteger hashPaddedPair(final MessageDigest digest,
						   final BigInteger N,
						   final BigInteger n1,
						   final BigInteger n2) {

		final int padLength = (N.bitLength() + 7) / 8;

		byte[] n1_bytes = toUnsignedPaddedByteArray(n1, padLength);

		byte[] n2_bytes = toUnsignedPaddedByteArray(n2, padLength);

		digest.update(n1_bytes);
		digest.update(n2_bytes);

		byte[] output = digest.digest();

		return new BigInteger(1, output);
	}



	/**
	 * Prevents instantiation.
	 */
	private BigIntegerUtils() {

		// do nothing
	}
}
