package com.nimbusds.srp6.fp;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SaltRoutines {

    /**
     * computes a salt of the size of the hashing function output size.
     */
    public static class SaltRoutineRandomBigInteger {
        static public BigInteger get(SecureRandom secureRandom, SRP6aProtocol.Parameters p) {
            // if the length of the hash is not available we default to 256 bits
            int byteLength = (p.digest.getDigestLength() == 0)? 256 / 8: p.digest.getDigestLength();
            return new BigInteger(p.digest.getDigestLength() * 8, secureRandom);
        }
    }
}
