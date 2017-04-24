package com.nimbusds.srp6.fp;

import java.math.BigInteger;

public class URoutines {
    public static class URoutineArguments {
        final BigInteger A;
        final BigInteger B;

        public URoutineArguments(final BigInteger A, final BigInteger B) {
            this.A = A;
            this.B = B;
        }

        public static URoutineArguments of(final BigInteger A, final BigInteger B) {
            return new URoutineArguments(A, B);
        }
    }

    public static URoutineArguments args(final BigInteger A, final BigInteger B) {
        return new URoutineArguments(A, B);
    }

    public static class URoutineFunctionOriginal {
        public static BigInteger apply(SRP6aProtocol.Parameters parameters, URoutineArguments uRoutineArguments) {
            return SRP6aProtocol.hashPaddedPair(parameters, uRoutineArguments.A, uRoutineArguments.B);
        }
    }
}
