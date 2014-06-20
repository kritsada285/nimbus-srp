package com.nimbusds.srp6;


import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;


/**
 * The base abstract class for client and server-side Secure Remote Password 
 * (SRP-6a) authentication sessions.
 *
 * @author Vladimir Dzhuvinov
 * @author John Kim
 */
public abstract class SRP6Session {
	

	/**
	 * The crypto parameters.
	 */
	protected SRP6CryptoParams cryptoParams;
	
	
	/**
	 * Source of randomness.
	 */
	protected final SecureRandom random = new SecureRandom();
	
	
	/**
	 * The SRP-6a authentication session timeout in seconds. If the 
	 * authenticating counterparty (server or client) fails to respond 
	 * within the specified time the session will be closed. Zero implies
	 * no timeout.
	 */
	private final int timeout;
	
	
	/**
	 * The last activity timestamp, from System.currentTimeMillis().
	 */
	private long lastActivity;
	
	
	/**
	 * The identity 'I' of the authenticating user.
	 */
	protected String userID = null;
	
	
	/**
	 * The password salt 's'.
	 */
	protected BigInteger s = null;
	
	
	/**
	 * The client public value 'A'.
	 */
	protected BigInteger A = null;
	
	
	/**
	 * The server public value 'B'.
	 */
	protected BigInteger B = null;
	
	
	/**
	 * The random scrambling parameter 'u'.
	 */
	protected BigInteger u = null;
	
	
	/**
	 * The multiplier 'k'.
	 */
	protected BigInteger k = null;
	
	
	/**
	 * The shared session key 'S'.
	 */
	protected BigInteger S = null;


	/**
	 * The client evidence message 'M1'.
	 */
	protected BigInteger M1 = null;


	/**
	 * The server evidence message 'M2'.
	 */
	protected BigInteger M2 = null;


	/**
	 * Routine for hashing the SRP messages.
	 */
	private HashRoutine hashRoutine = DefaultRoutines.getInstance();


	/**
	 * Routine for the hashed keys 'u' computation.
	 */
	private URoutine hashedKeysRoutine = DefaultRoutines.getInstance();


	/**
	 * Routine for the client evidence message 'M1' computation.
	 */
	private ClientEvidenceRoutine clientEvidenceRoutine = DefaultRoutines.getInstance();


	/**
	 * Routine for the server evidence message 'M2' computation.
	 */
	private ServerEvidenceRoutine serverEvidenceRoutine = DefaultRoutines.getInstance();


	/**
	 * Optional storage of arbitrary session attributes.
	 */
	private Map<String,Object> attributes = null;
	
	
	/**
	 * Creates a new SRP-6a authentication session.
	 *
	 * @param timeout The SRP-6a authentication session timeout in seconds. 
	 *                If the authenticating counterparty (server or client) 
	 *                fails to respond within the specified time the
	 *                session will be closed. If zero timeouts are
	 *                disabled.
	 */
	public SRP6Session(final int timeout) {
	
		if (timeout < 0)
			throw new IllegalArgumentException("The timeout must be zero (no timeout) or greater");
		
		this.timeout = timeout;
	}
	
	
	/**
	 * Creates a new SRP-6a authentication session, session timeouts are 
	 * disabled.
	 */
	public SRP6Session() {
	
		this(0);
	}
	
	
	/**
	 * Updates the last activity timestamp.
	 */
	protected void updateLastActivityTime() {
	
		lastActivity = System.currentTimeMillis();
	}
	
	
	/**
	 * Gets the last session activity timestamp, in milliseconds since 
	 * midnight, January 1, 1970 UTC (see System.currentTimeMillis()).
	 *
	 * @return The last activity timestamp.
	 */
	public long getLastActivityTime() {
	
		return lastActivity;
	}
	
	
	/**
	 * Returns {@code true} if the session has timed out, based on the 
	 * timeout configuration and the last activity timestamp.
	 *
	 * @return {@code true} if the session has timed out, else 
	 *         {@code false}.
	 */
	public boolean hasTimedOut() {
	
		if (timeout == 0)
			return false;
	
		final long now = System.currentTimeMillis();

		return now > lastActivity + (timeout * 1000);
	}
	
	
	/**
	 * Gets the SRP-6a crypto parameters for this session.
	 *
	 * @return The SRP-6a crypto parameters, {@code null} if undefined.
	 */
	public SRP6CryptoParams getCryptoParams() {
	
		return cryptoParams;
	}
	
	
	/**
	 * Gets the identity 'I' of the authenticating user.
	 *
	 * @return The user identity 'I', {@code null} if undefined.
	 */
	public String getUserID() {
	
		return userID;
	}
	
	
	/**
	 * Gets the SRP-6a authentication session timeout.
	 *
	 * @return The SRP-6a authentication session timeout, in seconds. Zero
	 *         implies to timeout.
	 */
	public int getTimeout() {
	
		return timeout;
	}


	/**
	 * Sets the principal hash 'H' routine. Must be set prior to
	 * {@link SRP6ClientSession.State#STEP_2} or
	 * {@link SRP6ServerSession.State#STEP_1}.
	 *
	 * @param hRoutine The principal hash 'H' routine. Must not be
	 *                 {@code null}.
	 */
	public void setHashRoutine(final HashRoutine hRoutine) {

		if (hRoutine == null)
			throw new IllegalArgumentException("The hash 'H' routine must not be null");

		hashRoutine = hRoutine;
	}


	/**
	 * Gets the principal hash 'H' routine.
	 *
	 * @return The principal hash 'H' routine.
	 */
	public HashRoutine getHashRoutine() {

		return hashRoutine;
	}
	
	
	/**
	 * Sets a routine to compute the client evidence message 'M1'. Must be
	 * set prior to {@link SRP6ClientSession.State#STEP_2} or
	 * {@link SRP6ServerSession.State#STEP_2}.
	 *
	 * @param m1Routine The client evidence message 'M1' routine. Must not
	 *                  be {@code null}.
	 */
	public void setClientEvidenceRoutine(final ClientEvidenceRoutine m1Routine) {

		if (m1Routine == null)
			throw new IllegalArgumentException("The client evidence message 'M1' routine must not be null");
	
		clientEvidenceRoutine = m1Routine;
	}
	
	
	/**
	 * Gets the routine to compute the client evidence message 'M1'.
	 *
	 * @return The client evidence message 'M1' routine.
	 */
	public ClientEvidenceRoutine getClientEvidenceRoutine() {
	
		return clientEvidenceRoutine;
	}
	
	
	/**
	 * Sets a routine to compute the server evidence message 'M2'. Must be
	 * set prior to {@link SRP6ClientSession.State#STEP_3} or
	 * {@link SRP6ServerSession.State#STEP_2}.
	 *
	 * @param m2Routine The server evidence message 'M2' routine. Must not
	 *                  be {@code null}.
	 */
	public void setServerEvidenceRoutine(final ServerEvidenceRoutine m2Routine) {

		if (m2Routine == null)
			throw new IllegalArgumentException("The server evidence message 'M2' routine must not be null");
	
		serverEvidenceRoutine = m2Routine;
	}
	
	
	/**
	 * Gets the routine to compute the server evidence message 'M2'.
	 *
	 * @return The server evidence message 'M2' routine.
	 */
	public ServerEvidenceRoutine getServerEvidenceRoutine() {
	
		return serverEvidenceRoutine;
	}


	/**
	 * Sets the custom routine to compute the random scrambling parameter
	 * 'u' as 'H(A | B)'. Must be set prior to
	 * {@link SRP6ServerSession.State#STEP_2}.
	 *
	 * @param uRoutine The random scrambling parameter 'u' routine. Must
	 *                 not be {@code null}.
	 */
	public void setHashedKeysRoutine(final URoutine uRoutine) {

		if (uRoutine == null)
			throw new IllegalArgumentException("The hashed keys 'u' routine must not be null");

		this.hashedKeysRoutine = uRoutine;
	}


	/**
	 * Gets the custom routine to compute the random scrambling parameter
	 * 'u' as 'H(A | B)'.
	 *
	 * @return The random scrambling parameter 'u' routine.
	 */
	public URoutine getHashedKeysRoutine() {

		return hashedKeysRoutine;
	}


	/**
	 * Gets the password salt 's'.
	 * 
	 * @return The salt 's' if available, else {@code null}.
	 */
	public BigInteger getSalt() {
	
		return s;
	}
	
	
	/**
	 * Gets the public client value 'A'.
	 *
	 * @return The public client value 'A' if available, else {@code null}.
	 */
	public BigInteger getPublicClientValue() {
	
		return A;
	}
	
	
	/**
	 * Gets the public server value 'B'.
	 *
	 * @return The public server value 'B' if available, else {@code null}.
	 */
	public BigInteger getPublicServerValue() {
	
		return B;
	}
	
	
	/**
	 * Gets the client evidence message 'M1'.
	 *
	 * @return The client evidence message 'M1' if available, else
	 *         {@code null}.
	 */
	public BigInteger getClientEvidenceMessage() {
	
		return M1;
	}
	
	
	/**
	 * Gets the server evidence message 'M2'.
	 *
	 * @return The server evidence message 'M2' if available, else
	 *         {@code null}.
	 */
	public BigInteger getServerEvidenceMessage() {
	
		return M2;
	}
	
	
	/**
	 * Gets the shared session key 'S' or its hash H(S).
	 *
	 * @param doHash If {@code true} the hash H(S) of the session key will
	 *               be returned instead of the raw value.
	 *
	 * @return The shared session key 'S' or its hash H(S). {@code null} 
	 *         will be returned if authentication failed or the method is
	 *         invoked in a session state when the session key 'S' has not
	 *         been computed yet.
	 */
	public BigInteger getSessionKey(final boolean doHash) {
	
		if (S == null)
			return null;
	
		if (doHash) {
			return new BigInteger(hashRoutine.hash(S.toByteArray()));
		} else {
			return S;
		}
	}
	
	
	/**
	 * Sets a session attribute. This method can be used to store arbitrary
	 * objects with this session and retrieve them later with 
	 * {@link #getAttribute}.
	 *
	 * @param key   The attribute key. Must not be {@code null}.
	 * @param value The attribute value. May be {@code null}.
	 */
	public void setAttribute(final String key, final Object value) {
	
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
	public Object getAttribute(final String key) {
	
		if (key == null)
			throw new IllegalArgumentException("The attribute key must not be null");
		
		if (attributes == null)
			return null;
		
		return attributes.get(key);
	}
}
