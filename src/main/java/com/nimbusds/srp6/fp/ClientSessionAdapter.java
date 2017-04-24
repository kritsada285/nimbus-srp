package com.nimbusds.srp6.fp;

import com.nimbusds.srp6.SRP6ClientCredentials;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6Exception;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Adapts the OO client session API to the new FP API
 */
public class ClientSessionAdapter {


    /**
     * Enumerates the states of a client-side SRP-6a authentication
     * session.
     */
    public static enum State {


        /**
         * The session is initialised and ready to begin authentication
         * by proceeding to {@link #STEP_1}.
         */
        INIT,


        /**
         * The authenticating user has input their identity 'I'
         * (username) and password 'P'. The session is ready to proceed
         * to {@link #STEP_2}.
         */
        STEP_1,


        /**
         * The user identity 'I' is submitted to the server which has
         * replied with the matching salt 's' and its public value 'B'
         * based on the user's password verifier 'v'. The session is
         * ready to proceed to {@link #STEP_3}.
         */
        STEP_2,


        /**
         * The client public key 'A' and evidence message 'M1' are
         * submitted and the server has replied with own evidence
         * message 'M2'. The session is finished (authentication was
         * successful or failed).
         */
        STEP_3
    }

    final SecureRandom secureRandom = new SecureRandom();
    final SRP6CryptoParams cryptoParams;
    final Optional<Integer> timeout;
    private Optional<String> I = Optional.empty();
    private Optional<String> password = Optional.empty();
    private Optional<BigInteger> salt = Optional.empty();
    private Optional<BigInteger> B = Optional.empty();
    private Optional<SRP6aProtocol.ClientSession> clientSession = Optional.empty();
    private Optional<BigInteger> M2 = Optional.empty();
    private Optional<SRP6aProtocol.Parameters> p = Optional.empty();

    long lastActivityTime = 0;

    public ClientSessionAdapter(SRP6CryptoParams cryptoParams, Optional<Integer> timeoutSeconds){
        this.cryptoParams = cryptoParams;
        this.timeout = timeoutSeconds;
    }

    /**
     * Gets the SRP-6a crypto parameters for this session.
     *
     * @return The SRP-6a crypto parameters, {@code null} if undefined.
     */
    public SRP6CryptoParams getCryptoParams() {
        return this.cryptoParams;
    }

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
        if (state != State.STEP_1)
            throw new IllegalStateException("State violation: Session must be in STEP_1 state");

        SRP6aProtocol.Parameters p;
        try {
            p = SRP6aProtocol.Parameters.of(config);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm 'H': " + config.H);
        }

        this.p = Optional.of(p);

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
        if (state != State.STEP_2)
            throw new IllegalStateException("State violation: Session must be in STEP_2 state");

        // Check timeout
        if (hasTimedOut())
            throw new SRP6Exception("Session timeout", SRP6Exception.CauseType.TIMEOUT);

        // here we do a raw get as we check we are in state 2 above
        final SRP6aProtocol.ClientSession session = clientSession.get();

        // here we do a raw get of this.p as we check that we are in state 2 above
        final BigInteger computedM2 = EvidenceRoutines.ServerEvidenceRoutine.apply(
                this.p.get(),
                EvidenceRoutines.ServerEvidenceRoutineArguments.of(
                        session.credentials.A,
                        session.credentials.M1,
                        session.S));

        if (! computedM2.equals(M2))
            throw new SRP6Exception("Bad server credentials", SRP6Exception.CauseType.BAD_CREDENTIALS);

        lastActivityTime = System.currentTimeMillis();
    }

    /**
     * Gets the last session activity timestamp, in milliseconds since
     * midnight, January 1, 1970 UTC (see System.currentTimeMillis()).
     *
     * @return The last activity timestamp.
     */
    public long getLastActivityTime() {
        return lastActivityTime;
    }

    /**
     * Returns {@code true} if the session has timed out, based on the
     * timeout configuration and the last activity timestamp.
     *
     * @return {@code true} if the session has timed out, else
     *         {@code false}.
     */
    public boolean hasTimedOut() {
        if (timeout.isPresent() == false)
            return false;

        final long now = System.currentTimeMillis();

        return now > lastActivityTime + (timeout.get() * 1000);
    }

    /**
     * Gets the identity 'I' of the authenticating user.
     *
     * @return The user identity 'I', {@code null} if undefined.
     */
    public String getUserID() {
        return this.I.orElse(null);
    }

    /**
     * Gets the SRP-6a authentication session timeout.
     *
     * @return The SRP-6a authentication session timeout, in seconds. Zero
     *         implies to timeout.
     */
    public int getTimeout() {
        return this.timeout.orElseThrow(new Supplier<AssertionError>() {
            @Override
            public AssertionError get() {
                return new AssertionError("session was not constructed with a timeout.");
            }
        });
    }

    /**
     * Gets the password salt 's'.
     *
     * @return The salt 's' if available, else {@code null}.
     */
    public BigInteger getSalt() {
        return this.salt.orElse(null);
    }

    /**
     * Gets the public client value 'A'.
     *
     * @return The public client value 'A' if available, else {@code null}.
     */
    public BigInteger getPublicClientValue() {
        if( this.clientSession.isPresent() ) {
            return this.clientSession.get().credentials.A;
        } else {
            return null;
        }
    }

    /**
     * Gets the public server value 'B'.
     *
     * @return The public server value 'B' if available, else {@code null}.
     */
    public BigInteger getPublicServerValue() {
        return this.B.orElse(null);
    }

    /**
     * Gets the client evidence message 'M1'.
     *
     * @return The client evidence message 'M1' if available, else
     *         {@code null}.
     */
    public BigInteger getClientEvidenceMessage() {
        if( this.clientSession.isPresent() ) {
            return this.clientSession.get().credentials.M1;
        } else {
            return null;
        }
    }

    /**
     * Gets the server evidence message 'M2'.
     *
     * @return The server evidence message 'M2' if available, else
     *         {@code null}.
     */
    public BigInteger getServerEvidenceMessage() {
        return this.M2.orElse(null);
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
            MessageDigest d = this.p.get().digest;
            d.reset();
            d.update(this.clientSession.get().S.toByteArray());
            return d.digest();
        } else {
            return null;
        }
    }

    /**
     * Optional storage of arbitrary session attributes.
     */
    private Map<String,Object> attributes = null;

    /**
     * Sets a session attribute. This method can be used to store arbitrary
     * objects with this session and retrieve them later with
     * {@link #getAttribute}.
     *  @param key   The attribute key. Must not be {@code null}.
     * @param value The attribute value. May be {@code null}.
     */
    public void setAttribute(String key, Object value) {

        if (key == null)
            throw new IllegalArgumentException("The attribute key must not be null");

        // create new attribute map on demand
        if (attributes == null)
            attributes = new HashMap<>();

        attributes.put(key, value);
    }

    /**
     * Gets a session attribute. This method can be used to retrieve
     * arbitrary objects stored with this session with
     * {@link #setAttribute}.
     *
     * @param key The attribute key. Must not be {@code null}.
     *
     * @return The attribute value, {@code null} if none was found by the
     *         specified key or its value is {@code null}.
     */
    public Object getAttribute(String key) {
        if (key == null)
            throw new IllegalArgumentException("The attribute key must not be null");

        if (attributes == null)
            return null;

        return attributes.get(key);
    }

    /**
     * The current SRP-6a auth state.
     */
    private State state = State.INIT;

    /**
     * Returns the current state of this SRP-6a authentication session.
     *
     * @return The current state.
     */
    public State getState() {
        return state;
    }

}
