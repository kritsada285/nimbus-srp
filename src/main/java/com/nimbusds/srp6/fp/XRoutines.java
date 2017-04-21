package com.nimbusds.srp6.fp;

import com.nimbusds.srp6.BigIntegerUtils;

import java.math.BigInteger;
import java.util.function.BiFunction;

public class XRoutines {

    public static class XRoutineArguments {
        final byte[] salt;
        final byte[] username;
        final byte[] password;

        public XRoutineArguments(byte[] salt, byte[] username, byte[] password) {
            this.salt = salt;
            this.username = username;
            this.password = password;
        }
    }

    public static XRoutineArguments args(byte[] salt, byte[] username, byte[] password) {
        return new XRoutineArguments(salt, username, password);
    }

    public static XRoutineArguments args(BigInteger salt, String username, String password) {
        return new XRoutineArguments(BigIntegerUtils.bigIntegerToBytes(salt),
                username.getBytes(SRP6aProtocol.UTF8),
                password.getBytes(SRP6aProtocol.UTF8));
    }


    /**
     * This implementation ignores the username whereas RFC 2945 and RFC 5054 include the username. Not including the username means that users can change their username (e.g. email) without having to reset their verifier. On the other had most systems confirm the user knows their password when changing the email for additional security. This means that they can easily create a new verifier at that point. This version is only suitable where it simply isn't possible to create a fresh verifier when the user changes the username (e.g. email). An example may be where the username controlled by some 3rd party system (e.g. the corporate email system). It is <b>not recommended</b> to use this version if it is possible to use the RFC version instead.
     */
    public static class XRoutineOriginal {

        public static BigInteger apply(SRP6aProtocol.Parameters p, XRoutineArguments args) {
            p.digest.reset();
            byte[] output = p.digest.digest(args.password);

            p.digest.update(args.salt);
            p.digest.update(output);

            return BigIntegerUtils.bigIntegerFromBytes(p.digest.digest());
        }
    }

    /**
     * This implements the RFC 2945 and RFC 5054 version args X. This means that if the user changes their username (e.g. email) you will have to create a fresh verifier. Most systems have the user confirm they know the password when you changing the username (e.g. email) for additional security. This ean that they can easily create a fresh verifier at that point.
     */
    public static class XRoutineRfc {

        public static BigInteger apply(SRP6aProtocol.Parameters p, XRoutineArguments args) {
            p.digest.reset();
            p.digest.update(args.username);
            p.digest.update((byte) ':');
            p.digest.update(args.password);

            byte[] output = p.digest.digest();

            p.digest.update(args.salt);
            output = p.digest.digest(output);

            return BigIntegerUtils.bigIntegerFromBytes(output);
        }

    }
}
