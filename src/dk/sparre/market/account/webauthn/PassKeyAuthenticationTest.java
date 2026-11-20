package dk.sparre.market.account.webauthn;

import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Duration;

public class PassKeyAuthenticationTest {
	private static final String DATA_JSON_URL = "https://portal.whiskyinvestdirect.com/account/security/__data.json";

	// Change if you want to test another credential.
	private static final int CREDENTIAL_DATABASE_ID = 1;

	private final CookieManager cookieManager;
	private final HttpClient httpClient;

	private PassKeyAuthenticationTest() {
		this.cookieManager = new CookieManager();
		this.httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
				.connectTimeout(Duration.ofSeconds(60)).cookieHandler(cookieManager).build();
	}

	public static void main(String[] args) {
		try {
			new PassKeyAuthenticationTest().run();
		} catch (Exception e) {
			System.err.println("PassKey authentication test failed: " + e.getMessage());
			e.printStackTrace();
			System.exit(1);
		}
	}

	private void run() throws Exception {
		try (Connection conn = DriverManager.getConnection(Secrets.DB_URL, Secrets.DB_USERNAME, Secrets.DB_PASSWORD)) {
			CredentialManager credentialManager = new CredentialManager(Secrets.getMasterAesKey());
			PassKeyAuthenticator authenticator = new PassKeyAuthenticator(httpClient, credentialManager);
			authenticator.authenticate(conn, CREDENTIAL_DATABASE_ID);
		}

		System.out.println("Session cookies stored: " + cookieManager.getCookieStore().getCookies().size());

		// Dump raw layout JSON from __data.json to verify the session is authenticated
		HttpRequest dataReq = HttpRequest.newBuilder().uri(URI.create(DATA_JSON_URL)).timeout(Duration.ofSeconds(60))
				.header("Accept", "application/json").GET().build();
		HttpResponse<String> dataResp = httpClient.send(dataReq,
				HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
		System.out.println("GET /__data.json status: " + dataResp.statusCode());
		for (HttpCookie cookie : cookieManager.getCookieStore().getCookies()) {
			System.out.printf("Cookie: %s | maxAge=%ds | secure=%s | httpOnly=%s%n", cookie.getName(),
					cookie.getMaxAge(), cookie.getSecure(), cookie.isHttpOnly());
		}
		System.out.println("Some account information:");
		System.out.println(dataResp.body());
	}
}
