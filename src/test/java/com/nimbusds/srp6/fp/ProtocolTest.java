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

    SecureRandom secureRandom = new SecureRandom();
    SRP6CryptoParams srp6CryptoParams = SRP6CryptoParams.getInstance();
    SRP6aProtocol.Parameters p = null;
    String username = new String("username");
    String password = new String("password");

    @Override
    protected void setUp() throws Exception {
        p = SRP6aProtocol.Parameters.of(srp6CryptoParams);
    }

    public void testFpClientWithOOServer() throws Exception {
        BigInteger salt = SaltRoutines.SaltRoutineRandomBigInteger.get(secureRandom, p);
        final BigInteger v = SRP6aProtocol.generateVerifier(SRP6aProtocol.Parameters.of(srp6CryptoParams), XRoutineOriginal::apply, salt, username, password);

        final SRP6ServerSession serverSession = new SRP6ServerSession(srp6CryptoParams);
        final BigInteger B = serverSession.step1(username, salt, v);

        final SRP6aProtocol.ClientSession clientSession = SRP6aProtocol.generateProofClient(
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

        final BigInteger expectedM2 = serverSession.step2(clientSession.credentials.A, clientSession.credentials.M1);

        final BigInteger actualM2 = EvidenceRoutines.ServerEvidenceRoutine.apply(p, ServerEvidenceRoutineArguments.of(clientSession.credentials.A, clientSession.credentials.M1, clientSession.S));

        assertEquals(expectedM2, actualM2);
    }

    public void testFpServerWithOOClient() throws Exception {
        BigInteger originalSalt = SaltRoutines.SaltRoutineRandomBigInteger.get(secureRandom, p);
        final SRP6ClientSession originalClientSession = new SRP6ClientSession();
        final BigInteger originalVerifier = (new SRP6VerifierGenerator(srp6CryptoParams)).generateVerifier(originalSalt, username, password);
        final SRP6aProtocol.ServerChallenge serverChallenge = SRP6aProtocol.generateServerChallenge(p, secureRandom, RandomKeyRoutines::randomKeyRfc50504, originalVerifier);
        originalClientSession.step1(username, password);
        SRP6ClientCredentials clientCredentials = originalClientSession.step2(srp6CryptoParams, originalSalt, serverChallenge.B);
        SRP6aProtocol.ServerSession serverSession = SRP6aProtocol.generateServerProof(p, URoutineFunctionOriginal::apply, originalVerifier, serverChallenge, clientCredentials);
        assertEquals(originalClientSession.getSessionKey(), serverSession.secretKeyRaw());
        originalClientSession.step3(serverSession.proof());
    }
}
