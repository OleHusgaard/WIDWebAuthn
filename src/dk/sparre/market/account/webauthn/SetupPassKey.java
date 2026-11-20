package dk.sparre.market.account.webauthn;

import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.Base64;
import java.util.Objects;
import java.util.Scanner;

public class SetupPassKey {
	private static final String BASE_URL = "https://portal.whiskyinvestdirect.com";

	private static final String SIGNIN_URL = BASE_URL + "/signin";
	private static final String SIGNIN_SUPERFORM_ID = "1p3ituu";
	private static final String AUTH_CODE_PAGE_URL = "https://portal.whiskyinvestdirect.com/auth/code";
	private static final String AUTH_CODE_VERIFY_URL = "https://portal.whiskyinvestdirect.com/auth/code?/verify";
	private static final String AUTH_CODE_SUPERFORM_ID = "1b9pqrk";

	private static final String SECURITY_URL = BASE_URL + "/account/security";
	private static final String STEP_UP_URL = BASE_URL + "/account/step-up";
	private static final String STEP_UP_SMS_URL = BASE_URL + "/account/step-up/sms";
	private static final String STEP_UP_VERIFY_URL = BASE_URL + "/account/step-up/verify";
	private static final String PASSKEY_URL = BASE_URL + "/passkey";

	private final Scanner scanner;
	private final CookieManager cookieManager;
	private final HttpClient httpClient;

	private SetupPassKey() {
		scanner = new Scanner(System.in, StandardCharsets.UTF_8);

		cookieManager = new CookieManager();
		httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofMinutes(1))
				.cookieHandler(cookieManager).build();
	}

	public static void main(String[] args) {
		try {
			new SetupPassKey().run();
		} catch (Exception e) {
			System.err.println("PassKey setup failed: " + e.getMessage());
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void run() throws Exception {
		authenticate();
		try (Connection conn = DriverManager.getConnection(Secrets.DB_URL, Secrets.DB_USERNAME, Secrets.DB_PASSWORD)) {
			conn.setAutoCommit(false);
			try {
				addPassKey(conn);
				conn.commit();
			} catch (Exception e) {
				conn.rollback();
				throw e;
			}
		}
	}

	private void authenticate() throws Exception {
		String formBody = "email=" + URLEncoder.encode(Secrets.ACCOUNT_NAME, StandardCharsets.UTF_8) + "&password="
				+ URLEncoder.encode(Secrets.PASSWORD, StandardCharsets.UTF_8) + "&__superform_id="
				+ SIGNIN_SUPERFORM_ID;
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(SIGNIN_URL)).timeout(Duration.ofSeconds(60))
				.header("Content-Type", "application/x-www-form-urlencoded").header("Accept", "application/json")
				.header("x-sveltekit-action", "true").header("Origin", "https://portal.whiskyinvestdirect.com")
				.header("Referer", SIGNIN_URL)
				.POST(HttpRequest.BodyPublishers.ofString(formBody, StandardCharsets.UTF_8)).build();
		HttpResponse<String> response = httpClient.send(request,
				HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
		System.out.println("Posted signin form. HTTP status: " + response.statusCode());
		System.out.println("Posted signin form.: " + response.body());
		if (response.statusCode() >= 400)
			throw new IllegalStateException("Initial signin failed with HTTP " + response.statusCode());

		request = HttpRequest.newBuilder().uri(URI.create(AUTH_CODE_PAGE_URL)).timeout(Duration.ofSeconds(60))
				.header("Accept", "text/html").header("Referer", SIGNIN_URL).GET().build();
		response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
		System.out.println("Loaded /auth/code. HTTP status: " + response.statusCode());
		if (response.statusCode() >= 400)
			throw new IllegalStateException("Failed to load /auth/code: HTTP " + response.statusCode());

		System.out.print("One-time verification code from mobile: ");
		String oneTimeCode = scanner.nextLine().trim();
		if (oneTimeCode.isEmpty())
			throw new RuntimeException("Empty one-time verification code.");

		formBody = "smsCode=" + URLEncoder.encode(oneTimeCode, StandardCharsets.UTF_8) + "&__superform_id="
				+ AUTH_CODE_SUPERFORM_ID;
		request = HttpRequest.newBuilder().uri(URI.create(AUTH_CODE_VERIFY_URL)).timeout(Duration.ofSeconds(60))
				.header("Content-Type", "application/x-www-form-urlencoded").header("Accept", "application/json")
				.header("x-sveltekit-action", "true").header("Origin", "https://portal.whiskyinvestdirect.com")
				.header("Referer", AUTH_CODE_PAGE_URL)
				.POST(HttpRequest.BodyPublishers.ofString(formBody, StandardCharsets.UTF_8)).build();
		response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
		System.out.println("Posted verification form. HTTP status: " + response.statusCode());
		System.out.println("Posted verification form. body: " + response.body());
		if (response.statusCode() >= 400 || response.body().contains("\"type\":\"failure\""))
			throw new RuntimeException("SMS verification failed: " + response.body());

		request = HttpRequest.newBuilder().uri(URI.create("https://portal.whiskyinvestdirect.com/"))
				.timeout(Duration.ofSeconds(60)).header("Accept", "text/html").header("Referer", AUTH_CODE_PAGE_URL)
				.GET().build();

		response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
		System.out.println("Authenticated home page status: " + response.statusCode() + ", cookies stored: "
				+ cookieManager.getCookieStore().getCookies().size());
	}

	private void addPassKey(Connection conn) throws Exception {
		// 1. Initial GET /passkey (triggers step_up_required state on the server)
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(PASSKEY_URL)).timeout(Duration.ofSeconds(60))
				.header("Accept", "application/json").header("Referer", SECURITY_URL).GET().build();
		HttpResponse<String> response = httpClient.send(request,
				HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
		System.out.println("Initial GET /passkey status: " + response.statusCode() + " (status 403 is expected). body: "
				+ response.body());

		// 2. POST /account/step-up {"action": "add-passkey"}
		response = postJson(STEP_UP_URL, SECURITY_URL, null, "{\"action\":\"add-passkey\"}");
		System.out.println("POST /account/step-up status: " + response.statusCode() + " body: " + response.body());
		if (response.statusCode() >= 400)
			throw new RuntimeException("Step-up initiation failed: HTTP " + response.statusCode());

		// 3. POST /account/step-up/sms {"action": "add-passkey"} to dispatch SMS
		response = postJson(STEP_UP_SMS_URL, SECURITY_URL, null, "{\"action\":\"add-passkey\"}");
		System.out.println("POST /account/step-up/sms status: " + response.statusCode() + " body: " + response.body());
		if (response.statusCode() >= 400)
			throw new RuntimeException("Step-up SMS trigger failed: HTTP " + response.statusCode());

		// 4. Prompt for the step-up SMS code and POST /account/step-up/verify
		System.out.print("Step-up verification code from mobile: ");
		String stepUpCode = scanner.nextLine().trim();
		if (!stepUpCode.matches("\\d{6}"))
			throw new RuntimeException("Expected a 6-digit step-up verification code.");

		String verifyJson = "{\"action\":\"add-passkey\",\"code\":\"" + stepUpCode + "\",\"factor\":\"sms\"}";
		response = postJson(STEP_UP_VERIFY_URL, SECURITY_URL, null, verifyJson);
		System.out
				.println("POST /account/step-up/verify status: " + response.statusCode() + " body: " + response.body());
		if (response.statusCode() >= 400)
			throw new RuntimeException("Step-up verification failed: HTTP " + response.statusCode());
		String stepUpToken = extractJsonField(response.body(), "\"stepUpToken\"\\s*:\\s*\"([^\"]+)\"");

		// 5. GET /passkey to retrieve PublicKeyCredentialCreationOptions
		request = HttpRequest.newBuilder().uri(URI.create(PASSKEY_URL)).timeout(Duration.ofSeconds(60))
				.header("Accept", "application/json").header("Referer", SECURITY_URL)
				.header("X-Step-Up-Token", stepUpToken).GET().build();
		response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
		System.out.println("GET /passkey options status: " + response.statusCode());
		if (response.statusCode() != 200)
			throw new RuntimeException(
					"Failed to fetch passkey creation options: HTTP " + response.statusCode() + " " + response.body());

		String challenge = extractJsonField(response.body(), "\"challenge\"\\s*:\\s*\"([^\"]+)\"");
		String rpId = extractJsonField(response.body(), "\"rp\"\\s*:\\s*\\{[^}]*?\"id\"\\s*:\\s*\"([^\"]+)\"");
		String userIdB64Url = extractJsonField(response.body(),
				"\"user\"\\s*:\\s*\\{[^}]*?\"id\"\\s*:\\s*\"([^\"]+)\"");
		byte[] userHandle = Base64.getUrlDecoder().decode(userIdB64Url);

		// 6. Generate ES256 keypair, encrypt private key, and persist in database
		CredentialManager credentialManager = new CredentialManager(Secrets.getMasterAesKey());
		Credential credential = credentialManager.createAndStore(conn, rpId, userHandle);

		// 7. Build WebAuthn attestation payload and POST to /passkey
		String registrationJson = WebAuthnRegistration.buildRegistrationJson(credential, challenge);
		response = postJson(PASSKEY_URL, SECURITY_URL, stepUpToken, registrationJson);
		System.out.println("POST /passkey status: " + response.statusCode() + " body: " + response.body());
		if (response.statusCode() >= 400)
			throw new RuntimeException(
					"Server rejected passkey registration: HTTP " + response.statusCode() + " " + response.body());

		System.out.println("Passkey registered and linked! WEBAUTHNCREDENTIALS.ID=" + credential.dbId());
	}

	private HttpResponse<String> postJson(String url, String referer, String stepUpToken, String jsonBody)
			throws Exception {
		HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(60))
				.header("Content-Type", "application/json").header("Accept", "application/json")
				.header("Origin", BASE_URL).header("Referer", referer);
		if (stepUpToken != null)
			builder = builder.header("X-Step-Up-Token", stepUpToken);
		HttpRequest request = builder.POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
				.build();
		return httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
	}

	private static String extractJsonField(String json, String regex) {
		java.util.regex.Matcher m = java.util.regex.Pattern.compile(regex).matcher(json);
		if (!m.find()) {
			throw new IllegalStateException("Could not extract field matching [" + regex + "] from JSON: " + json);
		}
		return m.group(1);
	}

	private static class WebAuthnRegistration {
		private static final Base64.Encoder B64URL_ENC = Base64.getUrlEncoder().withoutPadding();

		// CBOR prefix for COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2:
		// bstr(32)}
		private static final byte[] COSE_ES256_X_PREFIX = { (byte) 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58,
				0x20 };
		// CBOR prefix for {-3: bstr(32)}
		private static final byte[] COSE_ES256_Y_PREFIX = { 0x22, 0x58, 0x20 };

		// CBOR prefix for {"fmt": "none", "attStmt": {}, "authData": bstr(164)}
		// authData length = 32 (rpIdHash) + 1 (flags) + 4 (signCount) + 16 (AAGUID) + 2
		// (credIdLen) + 32 (credId) + 77 (COSE_Key) = 164 (0xA4)
		private static final byte[] ATTESTATION_NONE_PREFIX = { (byte) 0xA3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n',
				'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', (byte) 0xA0, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a',
				0x58, (byte) 0xA4 };

		/**
		 * Builds the PublicKeyCredential JSON payload for an ES256 credential with a
		 * 32-byte credentialId.
		 */
		public static String buildRegistrationJson(Credential credential, String challengeB64Url)
				throws NoSuchAlgorithmException {
			Objects.requireNonNull(credential, "credential must not be null");
			Objects.requireNonNull(challengeB64Url, "challengeB64Url must not be null");

			byte[] credId = credential.credentialId();
			if (credId.length != 32) {
				throw new IllegalArgumentException("Expected 32-byte credentialId, got " + credId.length);
			}

			// 1. clientDataJSON
			String clientDataJson = "{\"type\":\"webauthn.create\",\"challenge\":\""
					+ challengeB64Url.replace("\\", "\\\\").replace("\"", "\\\"")
					+ "\",\"origin\":\"https://portal.whiskyinvestdirect.com\",\"crossOrigin\":false}";
			String clientDataB64Url = B64URL_ENC.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8));

			// 2. Pack CBOR attestationObject + authenticatorData + ES256 COSE_Key in one
			// fixed buffer (29 + 164 = 193 bytes)
			byte[] rpIdHash = MessageDigest.getInstance("SHA-256")
					.digest(credential.rpId().getBytes(StandardCharsets.UTF_8));

			ByteBuffer buf = ByteBuffer.allocate(ATTESTATION_NONE_PREFIX.length + 164);
			buf.put(ATTESTATION_NONE_PREFIX);
			buf.put(rpIdHash);
			buf.put((byte) 0x45); // Flags: UP (0x01) | UV (0x04) | AT (0x40)
			buf.putInt(0); // signCount = 0
			buf.put(new byte[16]); // 16-byte zero AAGUID
			buf.putShort((short) credId.length); // 2-byte big-endian credentialId length (32)
			buf.put(credId);
			buf.put(COSE_ES256_X_PREFIX);
			buf.put(credential.getPublicKeyX());
			buf.put(COSE_ES256_Y_PREFIX);
			buf.put(credential.getPublicKeyY());

			String attestationObjectB64Url = B64URL_ENC.encodeToString(buf.array());
			String credIdB64Url = credential.credentialIdBase64Url();

			return """
					{
					  "id": "%s",
					  "rawId": "%s",
					  "type": "public-key",
					  "authenticatorAttachment": "platform",
					  "response": {
					    "clientDataJSON": "%s",
					    "attestationObject": "%s",
					    "transports": ["internal"]
					  },
					  "clientExtensionResults": {
					    "credProps": {
					      "rk": true
					    }
					  }
					}
					""".formatted(credIdB64Url, credIdB64Url, clientDataB64Url, attestationObjectB64Url);
		}
	}
}
