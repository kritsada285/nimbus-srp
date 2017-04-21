package com.nimbusds.srp6.fp;

import com.nimbusds.srp6.BigIntegerUtils;
import com.nimbusds.srp6.SRP6CryptoParams;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.function.BiFunction;

public class SRP6aProtocol {

    public static Charset getUTF8() {
        return Charset.forName("UTF8");
    }

    public static final Charset UTF8 = getUTF8();

    public final static class Parameters implements Serializable {
        final MessageDigest digest;
        final BigInteger g;
        final BigInteger N;

        public Parameters(String H, BigInteger g, BigInteger N) throws NoSuchAlgorithmException {
            this.digest = MessageDigest.getInstance(H);
            this.g = g;
            this.N = N;
        }

        public static Parameters of(final SRP6CryptoParams srp6CryptoParams) throws NoSuchAlgorithmException {
            return new Parameters(srp6CryptoParams.H, srp6CryptoParams.g, srp6CryptoParams.N);
        }
    }

    public static BigInteger generateVerifier(
            final Parameters p,
            final BiFunction<Parameters, XRoutines.XRoutineArguments, BigInteger> xRoutineFunction,
            final BigInteger salt,
            final String username,
            final String password){
        return generateVerifier(p, xRoutineFunction, BigIntegerUtils.bigIntegerToBytes(salt), username.getBytes(UTF8), password.getBytes(UTF8));
    }

    public static BigInteger generateVerifier(
            final Parameters p,
            final BiFunction<Parameters, XRoutines.XRoutineArguments, BigInteger> xRoutineFunction,
            final byte[] salt,
            final byte[] username,
            final byte[] password) {
        BigInteger x = xRoutineFunction.apply(p, XRoutines.args(salt, username, password));
        return p.g.modPow(x, p.N);
    }

    public static class Credentials {
        final String username;
        final BigInteger A;
        final BigInteger M1;

        public Credentials(String username, BigInteger A, BigInteger M1) {
            this.username = username;
            this.A = A;
            this.M1 = M1;
        }
    }

    public static class SecretAndCredentials {
        final BigInteger S;
        final Credentials credentials;
        public SecretAndCredentials(final BigInteger S, final Credentials credentials){
            this.S = S;
            this.credentials = credentials;
        }
    }

    /**
     * Pads a big integer with leading zeros up to the specified length.
     *
     * @param n      The big integer to pad. Must not be {@code null}.
     * @param length The required length args the padded big integer as a
     *               byte array.
     *
     * @return The padded big integer as a byte array.
     */
    public static byte[] getPadded(final BigInteger n, final int length) {

        byte[] bs = BigIntegerUtils.bigIntegerToBytes(n);

        if (bs.length < length) {
            byte[] tmp = new byte[length];
            System.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
            bs = tmp;
        }

        return bs;
    }

    public static BigInteger hashPaddedPair(final Parameters p, final BigInteger n1, final BigInteger n2) {
        final int padLength = (p.N.bitLength() + 7) / 8;

        byte[] n1_bytes = getPadded(n1, padLength);

        byte[] n2_bytes = getPadded(n2, padLength);

        p.digest.reset();

        p.digest.update(n1_bytes);
        p.digest.update(n2_bytes);

        return BigIntegerUtils.bigIntegerFromBytes(p.digest.digest());
    }

    public static BigInteger computeSessionKey(
            final BigInteger N,
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
     * Compute 'k' to RFC 5054. Note that 'k' is a public constant value so we can supply it to any
     * clients written in other languages we don't have to make the algorithm pluggable.
     *
     * @return The resulting multiplier 'k'.
     */
    public static BigInteger computeK(final Parameters p) {
        return hashPaddedPair(p, p.N, p.g);
    }

    public static SecretAndCredentials generateProofClient(
            final Parameters p,
            final SecureRandom secureRandom,
            final BiFunction<Parameters, SecureRandom, BigInteger> randomKeySupplier,
            final BiFunction<Parameters, XRoutines.XRoutineArguments, BigInteger> xRoutineFunction,
            final BiFunction<Parameters, URoutines.URoutineArguments, BigInteger> uRoutineFunction,
            final BiFunction<Parameters, EvidenceRoutines.ClientEvidenceRoutineArguments, BigInteger> cEvidenceRoutine,
            final BigInteger salt,
            final String username,
            final String password,
            final BigInteger B) {
        final BigInteger x = xRoutineFunction.apply(p, XRoutines.args(salt, username, password));
        final BigInteger a = randomKeySupplier.apply(p, secureRandom);
        final BigInteger A = p.g.modPow(a, p.N);;
        final BigInteger k = computeK(p);
        final BigInteger u = uRoutineFunction.apply(p, URoutines.args(A, B));
        final BigInteger S = computeSessionKey(p.N, p.g, k, x, u, a, B);
        final BigInteger M1 = cEvidenceRoutine.apply(p, EvidenceRoutines.args(username, salt, A, B, S ));
        return new SecretAndCredentials(S, new Credentials(username, A, M1));
    }
}