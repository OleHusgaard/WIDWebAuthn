package dk.sparre.market.account.webauthn;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PassKeyAuthenticator {
	private static final String BASE_URL = "https://portal.whiskyinvestdirect.com";
	private static final String SIGNIN_URL = BASE_URL + "/signin";
	private static final String SIGNIN_PASSKEY_URL = BASE_URL + "/signin/passkey";

	private final HttpClient httpClient;
	private final CredentialManager credentialManager;

	public PassKeyAuthenticator(HttpClient httpClient, CredentialManager credentialManager) {
		this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
		this.credentialManager = Objects.requireNonNull(credentialManager, "credentialManager must not be null");
	}

	/**
	 * Authenticates this authenticator's HttpClient session using the stored
	 * passkey credential.
	 */
	public void authenticate(Connection conn, int credentialId) {
		Objects.requireNonNull(conn, "conn must not be null");

		Credential credential;
		try {
			credential = credentialManager.loadCredential(conn, credentialId);
		} catch (GeneralSecurityException | SQLException e) {
			throw new RuntimeException("Failed to load WebAuthn credential " + credentialId, e);
		}

		URI passkeyUri = URI.create(SIGNIN_PASSKEY_URL);

		// 1. Fetch challengeId and WebAuthn request options
		HttpRequest request = HttpRequest.newBuilder().uri(passkeyUri).timeout(Duration.ofSeconds(60))
				.header("Accept", "application/json").header("Referer", SIGNIN_URL).GET().build();
		HttpResponse<String> response;
		try {
			response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new RuntimeException("Interrupted while fetching challengeId and WebAuthn request options", e);
		} catch (IOException e) {
			throw new RuntimeException("Failed to fetch challengeId and WebAuthn request options", e);
		}
		if (response.statusCode() != 200)
			throw new RuntimeException(
					"Failed to fetch passkey login options: HTTP " + response.statusCode() + " " + response.body());

		// 2. Atomically advance SIGN_COUNT before sending assertion
		long nextSignCount;
		try {
			nextSignCount = credentialManager.incrementSignCount(conn, credential.dbId());
			if (!conn.getAutoCommit())
				conn.commit();
		} catch (SQLException e) {
			throw new RuntimeException("Failed to increment sign count.", e);
		}

		// 3. Sign assertion
		String challengeId = extractJsonField(response.body(), "challengeId");
		String challenge = extractJsonField(response.body(), "challenge");
		String loginPayload;
		try {
			loginPayload = credential.buildLoginRequestJson(BASE_URL, challengeId, challenge, nextSignCount);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Failed to sign assertion.", e);
		}

		// 4. POST to /signin/passkey
		HttpRequest verifyReq = HttpRequest.newBuilder().uri(passkeyUri).timeout(Duration.ofSeconds(60))
				.header("Content-Type", "application/json").header("Accept", "application/json")
				.header("Origin", BASE_URL).header("Referer", SIGNIN_URL)
				.POST(HttpRequest.BodyPublishers.ofString(loginPayload, StandardCharsets.UTF_8)).build();
		HttpResponse<String> verifyResp;
		try {
			verifyResp = httpClient.send(verifyReq, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new RuntimeException("Interrupted while POSTing to /signin/passkey", e);
		} catch (IOException e) {
			throw new RuntimeException("Failed to POST to /signin/passkey", e);
		}
		if (verifyResp.statusCode() >= 400)
			throw new RuntimeException(
					"Passkey login rejected: HTTP " + verifyResp.statusCode() + " " + verifyResp.body());
	}

	private String extractJsonField(String json, String field) {
		String regex = "\"" + field + "\"\\s*:\\s*\"([^\"]+)\"";
		Matcher m = Pattern.compile(regex).matcher(json);
		if (!m.find())
			throw new RuntimeException("Could not extract field matching [" + regex + "] from JSON: " + json);
		return m.group(1);
	}
}