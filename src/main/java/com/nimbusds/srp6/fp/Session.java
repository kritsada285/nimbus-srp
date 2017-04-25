package com.nimbusds.srp6.fp;

import com.nimbusds.srp6.SRP6CryptoParams;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class Session {
    final SecureRandom secureRandom = new SecureRandom();
    final SRP6CryptoParams cryptoParams;
    final SRP6aProtocol.Parameters p;
    final Optional<Integer> timeout;
    /**
     * The current SRP-6a auth state.
     */
    protected State state = State.INIT;
    protected Optional<String> I = Optional.empty();
    protected Optional<String> password = Optional.empty();
    protected Optional<BigInteger> salt = Optional.empty();
    protected Optional<BigInteger> B = Optional.empty();
    protected Optional<SRP6aProtocol.Credentials> credentials = Optional.empty();

    protected Optional<BigInteger> M2 = Optional.empty();
    /**
     * The last session state change timestamp, from System.currentTimeMillis().
     */
    long lastActivityTime = 0;
    /**
     * Optional storage of arbitrary session attributes.
     */
    private Map<String,Object> attributes = null;

    public Session(final SRP6CryptoParams config, final Optional<Integer> timeoutSeconds) {
        this.cryptoParams = config;
        this.timeout = timeoutSeconds;
        try {
            this.p = SRP6aProtocol.Parameters.of(config);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm 'H': " + config.H);
        }
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
     * Gets the SRP-6a authentication session timeout.
     *
     * @return The SRP-6a authentication session timeout, in seconds. Zero
     *         implies no timeout. Use hasTimedOut to check time remaining.
     */
    public int getTimeout() {
        return this.timeout.orElse(0);
    }

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
     * Returns the current state of this SRP-6a authentication session.
     *
     * @return The current state.
     */
    public State getState() {
        return state;
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
        if( this.credentials.isPresent() ) {
            return this.credentials.get().A;
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
        if( this.credentials.isPresent() ) {
            return this.credentials.get().M1;
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
     * Enumerates the states of a session
     */
    public static enum State {
        INIT,

        STEP_1,

        STEP_2,

        STEP_3
    }
}
