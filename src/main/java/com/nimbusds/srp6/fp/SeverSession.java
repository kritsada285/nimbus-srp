package com.nimbusds.srp6.fp;

import com.nimbusds.srp6.*;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Adapts an OO session session API to the FP API
 */
public class SeverSession extends Session {

    public SeverSession(SRP6CryptoParams cryptoParams, Optional<Integer> timeoutSeconds) {
        super(cryptoParams, timeoutSeconds);
    }

    Optional<SRP6aProtocol.ServerChallenge> challenge = Optional.empty();
    Optional<BigInteger> v = Optional.empty();
    Optional<SRP6aProtocol.ServerSession> serverSession = Optional.empty();

    /**
     * Increments this SRP-6a authentication session to
     * {@link State#STEP_1}.
     *
     * <p>Argument origin:
     *
     * <ul>
     *     <li>From client: user identity 'I'.
     *     <li>From server database: matching salt 's' and password verifier
     *        'v' values.
     * </ul>
     *
     * @param userID The identity 'I' of the authenticating user. Must not
     *               be {@code null} or empty.
     * @param salt      The password salt 's'. Must not be {@code null}.
     * @param v      The password verifier 'v'. Must not be {@code null}.
     *
     * @return The server public value 'B'.
     *
     * @throws IllegalStateException If the mehod is invoked in a state
     *                               other than {@link State#INIT}.
     */
    public BigInteger step1(String userID, BigInteger salt, BigInteger v) {
        // Check current state
        if (state != State.INIT)
            throw new IllegalStateException("State violation: Session must be in INIT state");
        super.I = Optional.of(userID);
        super.salt = Optional.of(salt);
        this.v = Optional.of(v);
        challenge = Optional.of(SRP6aProtocol.generateServerChallenge(super.p, secureRandom, RandomKeyRoutines::randomKeyRfc50504, v));
        super.state = State.STEP_1;
        return challenge.get().B;
    }

    /**
     * Increments this SRP-6a authentication session to
     * {@link State#STEP_2}.
     *
     * <p>Argument origin:
     *
     * <ul>
     *     <li>From client: public value 'A' and evidence message 'M1'.
     * </ul>
     *
     * @param A  The client public value. Must not be {@code null}.
     * @param M1 The client evidence message. Must not be {@code null}.
     *
     * @return The server evidence message 'M2'.
     *
     * @throws SRP6Exception If the session has timed out, the client public
     *                       value 'A' is invalid or the user credentials
     *                       are invalid.
     *
     * @throws IllegalStateException If the method is invoked in a state
     *                               other than {@link State#STEP_1}.
     */
    public BigInteger step2(BigInteger A, BigInteger M1) throws SRP6Exception {
        if (state != State.STEP_1)
            throw new IllegalStateException("State violation: Session must be in STEP_1 state");
        super.credentials = Optional.of(new SRP6aProtocol.Credentials(super.I.get(), A, M1));
        serverSession = Optional.of(SRP6aProtocol.generateServerProof(
                p,
                URoutines.URoutineFunctionOriginal::apply,
                v.get(),
                challenge.get(),
                credentials.get()));
        super.state = State.STEP_3;
        return serverSession.get().M2;
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
        if( serverSession.isPresent() ) {
            return serverSession.get().secretKeyRaw();
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
        if( serverSession.isPresent() ) {
            return serverSession.get().secretKeyHashed();
        } else {
            return null;
        }
    }
}
