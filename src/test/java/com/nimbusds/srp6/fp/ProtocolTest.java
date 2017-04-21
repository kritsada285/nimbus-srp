package com.nimbusds.srp6.fp;

import com.nimbusds.srp6.*;
import com.nimbusds.srp6.fp.XRoutines.XRoutineOriginal;
import com.nimbusds.srp6.fp.XRoutines.XRoutineRfc;
import com.nimbusds.srp6.fp.URoutines.URoutineFunctionOriginal;
import com.nimbusds.srp6.fp.EvidenceRoutines.ClientEvidenceRoutine;
import com.nimbusds.srp6.fp.EvidenceRoutines.ServerEvidenceRoutineArguments;
import junit.framework.TestCase;

import java.math.BigInteger;
import java.security.SecureRandom;


public class ProtocolTest extends TestCase {
    public void testXRoutineOriginal() throws Exception {

        final SRP6CryptoParams srp6CryptoParams = SRP6CryptoParams.getInstance();

        final byte[] salt = (new String("salt")).getBytes("UTF8");
        final byte[] username = (new String("username")).getBytes("UTF8");
        final byte[] password = (new String("password")).getBytes("UTF8");

        final BigInteger expectedX = (new XRoutineWithUserIdentity()).computeX(srp6CryptoParams.getMessageDigestInstance(), salt, username, password);

        final BigInteger actualX = (new XRoutineRfc()).apply(SRP6aProtocol.Parameters.of(srp6CryptoParams), XRoutines.args(salt, username, password));

        assertEquals(expectedX, actualX);
    }

    public void testXRoutineRfc() throws Exception {

        final SRP6CryptoParams srp6CryptoParams = SRP6CryptoParams.getInstance();

        final byte[] salt = (new String("salt")).getBytes("UTF8");
        final byte[] username = (new String("username")).getBytes("UTF8");
        final byte[] password = (new String("password")).getBytes("UTF8");

        final BigInteger expectedX = (new SRP6Routines(){}).computeX(srp6CryptoParams.getMessageDigestInstance(), salt, password);

        final BigInteger actualX = (new XRoutineOriginal()).apply(SRP6aProtocol.Parameters.of(srp6CryptoParams), XRoutines.args(salt, username, password));

        assertEquals(expectedX, actualX);

    }

    public void testVerifier() throws Exception {
        final SRP6CryptoParams srp6CryptoParams = SRP6CryptoParams.getInstance();

        final byte[] salt = (new String("salt")).getBytes("UTF8");
        final byte[] username = (new String("username")).getBytes("UTF8");
        final byte[] password = (new String("password")).getBytes("UTF8");

        final BigInteger expectedV = (new SRP6VerifierGenerator(srp6CryptoParams)).generateVerifier(salt, username, password);

        final BigInteger actualV = SRP6aProtocol.generateVerifier(SRP6aProtocol.Parameters.of(srp6CryptoParams), XRoutineOriginal::apply, salt, username, password);

        assertEquals(expectedV, actualV);
    }

    public void testClientToServer() throws Exception {
        SecureRandom secureRandom = new SecureRandom();

        final SRP6CryptoParams srp6CryptoParams = SRP6CryptoParams.getInstance();

        SRP6aProtocol.Parameters p = SRP6aProtocol.Parameters.of(srp6CryptoParams);

        final BigInteger salt = SaltRoutines.SaltRoutineRandomBigInteger.get(secureRandom, p);
        final String username = new String("username");
        final String password = new String("password");

        final BigInteger v = SRP6aProtocol.generateVerifier(SRP6aProtocol.Parameters.of(srp6CryptoParams), XRoutineOriginal::apply, salt, username, password);

        final SRP6ServerSession serverSession = new SRP6ServerSession(srp6CryptoParams);
        final BigInteger B = serverSession.step1(username, salt, v);

        final SRP6aProtocol.SecretAndCredentials secretAndCredentials = SRP6aProtocol.generateProofClient(
                p,
                secureRandom,
                RandomKeyRoutines::randomKeyRfc50504,
                XRoutineOriginal::apply,
                URoutineFunctionOriginal::apply,
                ClientEvidenceRoutine::apply,
                salt,
                username,
                password,
                B
                );

        final BigInteger expectedM2 = serverSession.step2(secretAndCredentials.credentials.A, secretAndCredentials.credentials.M1);

        final BigInteger actualM2 = EvidenceRoutines.ServerEvidenceRoutine.apply(p, ServerEvidenceRoutineArguments.of(secretAndCredentials.credentials.A, secretAndCredentials.credentials.M1, secretAndCredentials.S));

        assertEquals(expectedM2, actualM2);
    }
}
