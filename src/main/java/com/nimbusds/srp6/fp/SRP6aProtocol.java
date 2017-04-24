package com.nimbusds.srp6.fp;

import com.nimbusds.srp6.BigIntegerUtils;
import com.nimbusds.srp6.SRP6ClientCredentials;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6Exception;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;
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
        final BigInteger k;

        public Parameters(
                final String H,
                final BigInteger g,
                final BigInteger N) throws NoSuchAlgorithmException {
            this.digest = MessageDigest.getInstance(H);
            this.g = g;
            this.N = N;
            this.k = SRP6aProtocol.computeK(this.digest, this.N, this.g);
        }

        public static Parameters of(final SRP6CryptoParams srp6CryptoParams) throws NoSuchAlgorithmException {
            return new Parameters(srp6CryptoParams.H, srp6CryptoParams.g, srp6CryptoParams.N);
        }
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

    public static class ClientSession {
        final BigInteger S;
        final Credentials credentials;
        public ClientSession(final BigInteger S, final Credentials credentials){
            this.S = S;
            this.credentials = credentials;
        }
    }

    public static class ServerChallenge {
        final BigInteger b;
        final BigInteger B;
        public ServerChallenge(final BigInteger b, final BigInteger B){
            this.B = B;
            this.b = b;
        }
        public BigInteger getPublicEphemeralKey(){
            return this.B;
        }
        public BigInteger getPrivateEphemeralKey(){
            return this.b;
        }
    }

    public static class ServerSession {
        public final Parameters p;
        public final BigInteger M2;
        // not public so that folks access it via a getter which indicates that its secret.
        final BigInteger S;
        public ServerSession(Parameters p, final BigInteger S, final BigInteger M2){
            this.p = p;
            this.S = S;
            this.M2 = M2;
        }
        public BigInteger secretKeyRaw(){
            return  this.S;
        }
        public byte[] secretKeyHashed(){
            p.digest.reset();
            p.digest.update(this.S.toByteArray());
            return p.digest.digest();
        }

        public BigInteger proof() {
            return this.M2;
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
        checkParameters(p);
        BigInteger x = xRoutineFunction.apply(p, XRoutines.args(salt, username, password));
        return p.g.modPow(x, p.N);
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
    public static BigInteger computeK(final MessageDigest digest, final BigInteger N, final BigInteger g) {

        final int padLength = (N.bitLength() + 7) / 8;

        byte[] n1_bytes = getPadded(N, padLength);

        byte[] n2_bytes = getPadded(g, padLength);

        digest.reset();

        digest.update(n1_bytes);
        digest.update(n2_bytes);

        return BigIntegerUtils.bigIntegerFromBytes(digest.digest());
    }

    /**
     * S = (S - (k * g^x)) ^ (a + (u * x)) %N
     * M1 = H(A, S, S)
     *
     * @param p
     * @param secureRandom
     * @param randomKeySupplier
     * @param xRoutineFunction
     * @param uRoutineFunction
     * @param cEvidenceRoutine
     * @param salt
     * @param username
     * @param password
     * @param B
     * @return ClientSession with the shared secret key S and the credentials {A,M1}
     */
    public static ClientSession generateProofClient(
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
        checkParameters(p);
        final BigInteger x = xRoutineFunction.apply(p, XRoutines.args(salt, username, password));
        final BigInteger a = randomKeySupplier.apply(p, secureRandom);
        final BigInteger A = p.g.modPow(a, p.N);
        final BigInteger u = uRoutineFunction.apply(p, URoutines.args(A, B));
        final BigInteger S = computeSessionKey(p.N, p.g, p.k, x, u, a, B);
        final BigInteger M1 = cEvidenceRoutine.apply(p, EvidenceRoutines.args(Optional.of(username), Optional.of(salt), A, B, S ));
        return new ClientSession(S, new Credentials(username, A, M1));
    }

    public static void checkServerPrivateValue(BigInteger b) {
        if( b == null ) throw new IllegalArgumentException("The server private ephemeral value 'b' must not be null.");
        if( b.compareTo(BigInteger.ZERO) == 0) throw new IllegalArgumentException("The server private ephemeral value 'b' must not be zero.");
    }

    public static final int SHA1_BIT_LENGTH = 160;

    public static void checkNotNullOrLessThanOne(String parameterName, BigInteger bigInteger){
        if( bigInteger == null) throw new IllegalArgumentException(String.format("The parameter '%s' must not be null.", parameterName));
        if( bigInteger.compareTo(BigInteger.ONE) < 0) throw new IllegalArgumentException(String.format("The parameters '%s' must not be less than 1.", parameterName));
    }

    public static void checkParameters(Parameters p){
        if( p == null) throw new IllegalArgumentException("The SRP6 parameters 'p' must not be null.");
        if( p.digest == null) throw new IllegalArgumentException("The SRP6 parameters messages digest 'H' must not be null.");

        checkNotNullOrLessThanOne("k", p.k);
        checkNotNullOrLessThanOne("g", p.g);
        checkNotNullOrLessThanOne("N", p.N);

        int digestLength = (p.digest.getDigestLength() == 0)? SHA1_BIT_LENGTH: p.digest.getDigestLength();
        if( p.N.bitLength() < digestLength) throw new IllegalArgumentException(String.format("The SRP6 parameters safe prime 'N' bit length is {} but should not be less than the actual (or estimated) hash bit length which is {}.", p.N.bitLength(), digestLength));
    }

    /**
     * Computes the public server value S = k * v + g^b (mod N)
     *
     * <p>Specification: RFC 5054.
     *
     * @param v The password verifier 'v'. Must not be {@code null} or less than 1.
     *
     * @return The public server value 'S'.
     */
    public static ServerChallenge generateServerChallenge(
            final Parameters p,
            final SecureRandom secureRandom,
            final BiFunction<Parameters, SecureRandom, BigInteger> randomKeySupplier,
            final BigInteger v
    ) {
        checkParameters(p);
        checkNotNullOrLessThanOne("v", v);
        BigInteger b = randomKeySupplier.apply(p, secureRandom);
        checkServerPrivateValue(b);

        return new ServerChallenge(b, p.g.modPow(b, p.N).add(v.multiply(p.k)).mod(p.N));
    }

    /**
     * S = (A * v^u) ^ b (mod N)
     * M1 = H(A, S, S)
     * M2 = H(A, M1, S)
     * @param p
     * @param v
     * @param challenge
     * @param clientCredentials
     * @return
     */
    public static ServerSession generateServerProof(
            final Parameters p,
            final BiFunction<Parameters, URoutines.URoutineArguments, BigInteger> uRoutineFunction,
            final BigInteger v,
            final ServerChallenge challenge,
            final SRP6ClientCredentials clientCredentials) throws SRP6Exception {
        checkValidA(p, clientCredentials.A);
        checkParameters(p);
        checkNotNullOrLessThanOne("v", v);
        BigInteger u = uRoutineFunction.apply(p, URoutines.URoutineArguments.of(clientCredentials.A, challenge.B));
        BigInteger S = v.modPow(u, p.N).multiply(clientCredentials.A).modPow(challenge.b, p.N);
        BigInteger M1 = EvidenceRoutines.ClientEvidenceRoutine.apply(p, EvidenceRoutines.ClientEvidenceRoutine.of(clientCredentials.A, challenge.B, S));
        if( M1.compareTo(clientCredentials.M1) != 0) throw new SRP6Exception("Bad client credentials", SRP6Exception.CauseType.BAD_CREDENTIALS);
        BigInteger M2 = EvidenceRoutines.ServerEvidenceRoutine.apply(p, EvidenceRoutines.ServerEvidenceRoutineArguments.of(clientCredentials.A, M1, S));
        return new ServerSession(p, S, M2);
    }

    private static void checkValidA(final Parameters p, final BigInteger A) {
        if( A == null ) throw new IllegalArgumentException("parameter 'A' must not be null");
        if( A.mod(p.N) == BigInteger.ZERO ) throw new IllegalArgumentException("parameter 'A' invalid as A.mod(N)==0");
    }
}