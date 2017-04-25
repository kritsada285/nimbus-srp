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
import java.util.Arrays;
import java.util.Optional;


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
        final BigInteger v = SRP6aProtocol.generateVerifier(
                SRP6aProtocol.Parameters.of(srp6CryptoParams),
                XRoutineOriginal::apply,
                salt,
                username,
                password);

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

        final BigInteger expectedM2 = serverSession.step2(
                clientSession.credentials.A,
                clientSession.credentials.M1);

        final BigInteger actualM2 = EvidenceRoutines.ServerEvidenceRoutine.apply(
                p,
                ServerEvidenceRoutineArguments.of(
                        clientSession.credentials.A,
                        clientSession.credentials.M1,
                        clientSession.S));

        assertEquals(expectedM2, actualM2);
    }

    public void testFpClientSessionWithOOServer() throws Exception {
        BigInteger salt = SaltRoutines.SaltRoutineRandomBigInteger.get(secureRandom, p);

        final BigInteger v = SRP6aProtocol.generateVerifier(
                SRP6aProtocol.Parameters.of(srp6CryptoParams),
                XRoutineOriginal::apply,
                salt,
                username,
                password);

        final SRP6ServerSession serverSession = new SRP6ServerSession(srp6CryptoParams);

        final BigInteger B = serverSession.step1(username, salt, v);

        final ClientSession fpAdapter = new ClientSession(srp6CryptoParams, Optional.empty());

        fpAdapter.step1(username, password);

        final SRP6ClientCredentials clientCredentials = fpAdapter.step2(srp6CryptoParams, salt, B);

        final BigInteger M2 = serverSession.step2(clientCredentials.A, clientCredentials.M1);

        fpAdapter.step3(M2);

    }

    public void testFpServerWithOOClient() throws Exception {
        final BigInteger originalSalt = SaltRoutines.SaltRoutineRandomBigInteger.get(secureRandom, p);

        final SRP6ClientSession originalClientSession = new SRP6ClientSession();

        originalClientSession.step1(username, password);

        final BigInteger originalVerifier = (new SRP6VerifierGenerator(srp6CryptoParams)).generateVerifier(originalSalt, username, password);

        final SRP6aProtocol.ServerChallenge serverChallenge = SRP6aProtocol.generateServerChallenge(
                p,
                secureRandom,
                RandomKeyRoutines::randomKeyRfc50504,
                originalVerifier);


        final SRP6ClientCredentials clientCredentials = originalClientSession.step2(srp6CryptoParams, originalSalt, serverChallenge.B);

        final SRP6aProtocol.ServerSession serverSession = SRP6aProtocol.generateServerProof(
                p,
                URoutineFunctionOriginal::apply,
                originalVerifier,
                serverChallenge,
                username,
                clientCredentials);

        assertEquals(originalClientSession.getSessionKey(), serverSession.secretKeyRaw());

        final byte[] cKey = originalClientSession.getSessionKeyHash();
        final byte[] sKey = serverSession.secretKeyHashed();

        assertNotNull("originalClientSession.getSessionKeyHash()", cKey);

        assertNotNull("serverSession.secretKeyHashed()", sKey);

        assertTrue(str(cKey)+"\n"+str(sKey), Arrays.equals(cKey, sKey));

        originalClientSession.step3(serverSession.proof());
    }

    public void testFpServerSessionWithOOClient() throws Exception {
        final BigInteger originalSalt = SaltRoutines.SaltRoutineRandomBigInteger.get(secureRandom, p);

        final SRP6ClientSession originalClientSession = new SRP6ClientSession();

        originalClientSession.step1(username, password);

        final BigInteger originalVerifier = (new SRP6VerifierGenerator(srp6CryptoParams)).generateVerifier(originalSalt, username, password);

        final SeverSession serverAdapter = new SeverSession(srp6CryptoParams, Optional.empty());

        final BigInteger B = serverAdapter.step1(username, originalSalt, originalVerifier);

        final SRP6ClientCredentials clientCredentials = originalClientSession.step2(srp6CryptoParams, originalSalt, B);

        final BigInteger M2 = serverAdapter.step2(clientCredentials.A, clientCredentials.M1);

        originalClientSession.step3(M2);

        assertEquals(originalClientSession.getSessionKey(), serverAdapter.getSessionKey());

        final byte[] cKey = originalClientSession.getSessionKeyHash();
        final byte[] sKey = serverAdapter.getSessionKeyHash();

        assertNotNull("originalClientSession.getSessionKeyHash()", cKey);
        assertNotNull("serverAdapter.getSessionKeyHash()", sKey);

        assertTrue(str(cKey)+"\n"+str(sKey), Arrays.equals(cKey, sKey));
    }

    public static String str(byte[] cKey) {
        StringBuffer str = new StringBuffer();
        for( byte b : cKey) {
            str.append(b);
            str.append(',');
        }
        return str.toString();
    }
}
