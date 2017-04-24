package com.nimbusds.srp6.fp;

import com.nimbusds.srp6.BigIntegerUtils;

import java.math.BigInteger;
import java.util.Optional;

public class EvidenceRoutines {
    public static class ClientEvidenceRoutineArguments {
        public final Optional<String> I;
        public final Optional<BigInteger> salt;
        public final BigInteger A;
        public final BigInteger B;
        public final BigInteger S;
        public ClientEvidenceRoutineArguments(
                final Optional<String> I,
                final Optional<BigInteger> salt,
                final BigInteger A,
                final BigInteger B,
                final BigInteger S) {
            this.I = I;
            this.salt = salt;
            this.A = A;
            this.B = B;
            this.S = S;
        }
    }

    public static ClientEvidenceRoutineArguments args(
            final Optional<String> I,
            final Optional<BigInteger> salt,
            final BigInteger A,
            final BigInteger B,
            final BigInteger S) {
        return new ClientEvidenceRoutineArguments(I, salt, A, B, S);
    }

    public static class ClientEvidenceRoutine {
        public static BigInteger apply(SRP6aProtocol.Parameters p, ClientEvidenceRoutineArguments args) {
            return tripleHash(p, BigIntegerUtils.bigIntegerToBytes(args.A), BigIntegerUtils.bigIntegerToBytes(args.B), BigIntegerUtils.bigIntegerToBytes(args.S));
        }

        public static ClientEvidenceRoutineArguments of(BigInteger a, BigInteger b, BigInteger s) {
            return new ClientEvidenceRoutineArguments(Optional.empty(), Optional.empty(), a, b, s);
        }
    }

    public static class ServerEvidenceRoutineArguments {
        public final BigInteger A;
        public final BigInteger M1;
        public final BigInteger S;

        public ServerEvidenceRoutineArguments(
                final BigInteger A,
                final BigInteger M1,
                final BigInteger S) {
            this.A = A;
            this.M1 = M1;
            this.S = S;
        }

        final static ServerEvidenceRoutineArguments of(
                final BigInteger A,
                final BigInteger M1,
                final BigInteger S){
            return new ServerEvidenceRoutineArguments(A, M1, S);
        }
    }

    public static class ServerEvidenceRoutine {
        public static BigInteger apply(SRP6aProtocol.Parameters p, ServerEvidenceRoutineArguments args) {
            return tripleHash(p, BigIntegerUtils.bigIntegerToBytes(args.A), BigIntegerUtils.bigIntegerToBytes(args.M1), BigIntegerUtils.bigIntegerToBytes(args.S));
        }
    }

    public static BigInteger tripleHash(SRP6aProtocol.Parameters p, byte[] one, byte[] two, byte[] three) {
        p.digest.reset();
        p.digest.update(one);
        p.digest.update(two);
        p.digest.update(three);
        return BigIntegerUtils.bigIntegerFromBytes(p.digest.digest());
    }
}
