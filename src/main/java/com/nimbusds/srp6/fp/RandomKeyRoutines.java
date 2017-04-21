package com.nimbusds.srp6.fp;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Supplier;

public class RandomKeyRoutines {

    /**
     * Concrete RFC 5054 implementation of the the secure private key generator function.
     * The random number will be in the range `[1,N)`
     */
    public static BigInteger randomKeyRfc50504(final SRP6aProtocol.Parameters p, final SecureRandom secureRandom) {
        final int minBits = Math.max(256, p.N.bitLength());
        BigInteger r = BigInteger.ZERO;
        while (BigInteger.ZERO.equals(r)) {
            r = (new BigInteger(minBits, secureRandom)).mod(p.N);
        }
        return r;
    }
}
