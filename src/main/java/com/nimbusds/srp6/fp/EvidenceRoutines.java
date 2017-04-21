package com.nimbusds.srp6.fp;

import com.nimbusds.srp6.BigIntegerUtils;

import java.math.BigInteger;

public class EvidenceRoutines {
    public static class ClientEvidenceRoutineArguments {
        public final String I;
        public final BigInteger salt;
        public final BigInteger A;
        public final BigInteger B;
        public final BigInteger S;
        public ClientEvidenceRoutineArguments(
                final String I,
                final BigInteger salt,
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
            final String I,
            final BigInteger salt,
            final BigInteger A,
            final BigInteger B,
            final BigInteger S) {
        return new ClientEvidenceRoutineArguments(I, salt, A, B, S);
    }

    public static class ClientEvidenceRoutine {
        public static BigInteger apply(SRP6aProtocol.Parameters p, ClientEvidenceRoutineArguments args) {
            p.digest.reset();
            p.digest.update(BigIntegerUtils.bigIntegerToBytes(args.A));
            p.digest.update(BigIntegerUtils.bigIntegerToBytes(args.B));
            p.digest.update(BigIntegerUtils.bigIntegerToBytes(args.S));
            return BigIntegerUtils.bigIntegerFromBytes(p.digest.digest());
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
            p.digest.reset();
            p.digest.update(BigIntegerUtils.bigIntegerToBytes(args.A));
            p.digest.update(BigIntegerUtils.bigIntegerToBytes(args.M1));
            p.digest.update(BigIntegerUtils.bigIntegerToBytes(args.S));

            return BigIntegerUtils.bigIntegerFromBytes(p.digest.digest());
        }
    }
}
