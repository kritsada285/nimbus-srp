package com.nimbusds.srp6.fp;

import com.nimbusds.srp6.SRP6ClientCredentials;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6Exception;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Optional;

/**
 * Adapts an OO client session API to the FP API
 */
public class ClientSession extends Session {

    public ClientSession(SRP6CryptoParams cryptoParams, Optional<Integer> timeoutSeconds){
        super(cryptoParams, timeoutSeconds);
    }

    protected Optional<SRP6aProtocol.ClientSession> clientSession = Optional.empty();

    /**
     * Records the identity 'I' and password 'P' of the authenticating
     * user. The session is incremented to {@link State#STEP_1}.
     *
     * <p>Argument origin:
     *
     * <ul>
     *     <li>From user: user identity 'I' and password 'P'.
     * </ul>
     *
     * @param userID   The identity 'I' of the authenticating user, UTF-8
     *                 encoded. Must not be {@code null} or empty.
     * @param password The user password 'P', UTF-8 encoded. Must not be
     *                 {@code null}.
     *
     * @throws IllegalStateException If the method is invoked in a state
     *                               other than {@link State#INIT}.
     */
    public void step1(final String userID, final String password) {
        this.I = Optional.of(userID);
        this.password = Optional.of(password);
        state = State.STEP_1;
        lastActivityTime = System.currentTimeMillis();
    }

    /**
     * Receives the password salt 's' and public value 'B' from the server.
     * The SRP-6a crypto parameters are also set. The session is incremented
     * to {@link State#STEP_2}.
     *
     * <p>Argument origin:
     *
     * <ul>
     *     <li>From server: password salt 's', public value 'B'.
     *     <li>From server or pre-agreed: crypto parameters prime 'N',
     *         generator 'g' and hash function 'H'.
     * </ul>
     *
     * @param config The SRP-6a crypto parameters. Must not be {@code null}.
     * @param s      The password salt 's'. Must not be {@code null}.
     * @param B      The public server value 'B'. Must not be {@code null}.
     *
     * @return The client credentials consisting of the client public key
     *         'A' and the client evidence message 'M1'.
     *
     * @throws IllegalStateException If the method is invoked in a state
     *                               other than {@link State#STEP_1}.
     * @throws SRP6Exception         If the session has timed out or the
     *                               public server value 'B' is invalid.
     */
    public SRP6ClientCredentials step2(SRP6CryptoParams config, BigInteger salt, BigInteger B) throws SRP6Exception {

        // Check current state
        if (getState() != State.STEP_1)
            throw new IllegalStateException("State violation: Session must be in STEP_1 state");

        this.salt = Optional.of(salt);
        this.B = Optional.of(B);

        SRP6aProtocol.ClientSession session = SRP6aProtocol.generateProofClient(
                p,
                secureRandom,
                RandomKeyRoutines::randomKeyRfc50504,
                XRoutines.XRoutineOriginal::apply,
                URoutines.URoutineFunctionOriginal::apply,
                EvidenceRoutines.ClientEvidenceRoutine::apply,
                salt,
                this.I.get(),
                this.password.get(),
                B

        );

        this.clientSession = Optional.of(session);

        lastActivityTime = System.currentTimeMillis();

        this.state = State.STEP_2;

        return new SRP6ClientCredentials(session.credentials.A, session.credentials.M1);
    }

    /**
     * Receives the server evidence message 'M1'. The session is
     * incremented to {@link State#STEP_3}.
     *
     * <p>
     * Argument origin:
     *
     * <ul>
     * <li>From server: evidence message 'M2'.
     * </ul>
     *
     * @param M2 The server evidence message 'M2'. Must not be
     *           {@code null}.
     *
     * @throws IllegalStateException If the method is invoked in a state
     *                               other than {@link State#STEP_2}.
     * @throws SRP6Exception         If the session has timed out or the
     *                               server evidence message 'M2' is
     *                               invalid.
     */
    public void step3(BigInteger M2) throws SRP6Exception {
        if (M2 == null)
            throw new IllegalArgumentException("The server evidence message 'M2' must not be null");

        this.M2 = Optional.of(M2);

        // Check current state
        if (getState() != State.STEP_2)
            throw new IllegalStateException("State violation: Session must be in STEP_2 state");

        // Check timeout
        if (hasTimedOut())
            throw new SRP6Exception("Session timeout", SRP6Exception.CauseType.TIMEOUT);

        // here we do a raw get as we check we are in state 2 above
        final SRP6aProtocol.ClientSession session = clientSession.get();

        // here we do a raw get of this.p as we check that we are in state 2 above
        final BigInteger computedM2 = EvidenceRoutines.ServerEvidenceRoutine.apply(
                this.p,
                EvidenceRoutines.ServerEvidenceRoutineArguments.of(
                        session.credentials.A,
                        session.credentials.M1,
                        session.S));

        if (! computedM2.equals(M2))
            throw new SRP6Exception("Bad server credentials", SRP6Exception.CauseType.BAD_CREDENTIALS);

        lastActivityTime = System.currentTimeMillis();
    }

    /**
     * Gets the shared session key 'S'
     *
     * @return The shared session key 'S'. {@code null}
     *         will be returned if authentication failed or the method is
     *         invoked in a session state when the session key 'S' has not
     *         been computed yet.
     */
    public BigInteger getSessionKey() {
        if( this.clientSession.isPresent() ) {
            return this.clientSession.get().S;
        } else {
            return null;
        }
    }

    /**
     * Gets the hash of the shared session key H(S).
     *
     * @return The hash of the shared session key H(S). {@code null}
     *         will be returned if authentication failed or the method is
     *         invoked in a session state when the session key 'S' has not
     *         been computed yet.
     */
    public byte[] getSessionKeyHash() {
        if( this.clientSession.isPresent() ) {
            MessageDigest d = this.p.digest;
            d.reset();
            d.update(this.clientSession.get().S.toByteArray());
            return d.digest();
        } else {
            return null;
        }
    }

}
