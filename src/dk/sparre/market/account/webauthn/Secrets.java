package dk.sparre.market.account.webauthn;

import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Make sure to change the six constants defined in the top of this class.
 */
class Secrets {
	static final String DB_URL = "jdbc:mysql://localhost:3306/market";
	static final String DB_USERNAME = "somebody";
	static final String DB_PASSWORD = "secret";
	static final String ACCOUNT_NAME = "somebody@somewhere.net";
	static final String PASSWORD = "Secret";
	static final String SALT = "Long secret. Use 'openssl rand -base64 48' to generate.";

	private static volatile SecretKey masterAesKey = null;

	/**
	 * Recommended way to get the master AES key for secret key encryption in the
	 * database. The user should enter the same pin code each time.
	 */
	static SecretKey getMasterAesKey() {
		synchronized (CredentialManager.class) {
			if (masterAesKey != null)
				return masterAesKey;
			char[] pinCode;
			Console console = System.console();
			if (console != null) {
				pinCode = console.readPassword("Pin code: ");
				if (pinCode == null || pinCode.length == 0) {
					throw new IllegalArgumentException("Empty pin code.");
				}
			} else {
				// Insecure fallback in case this is running in an IDE.
				@SuppressWarnings("resource")
				Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
				System.out.print("Pin code: ");
				String pinCodeStr = scanner.nextLine().trim();
				if (pinCodeStr.isEmpty())
					throw new RuntimeException("Empty pin code.");
				pinCode = pinCodeStr.toCharArray();
			}

			byte[] derivedKeyBytes = null;
			try {
				byte[] salt = Base64.getDecoder().decode(SALT);
				// Lots of iterations to avoid somebody brute-forcing the pin code.
				PBEKeySpec spec = new PBEKeySpec(pinCode, salt, 600000, 256);
				try {
					SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
					derivedKeyBytes = factory.generateSecret(spec).getEncoded();
					masterAesKey = new SecretKeySpec(derivedKeyBytes, "AES");
					return masterAesKey;
				} finally {
					spec.clearPassword();
				}
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException("Failed to derive AES-256 master key", e);
			} finally {
				Arrays.fill(pinCode, '\0');
				if (derivedKeyBytes != null) {
					Arrays.fill(derivedKeyBytes, (byte) 0);
				}
			}
		}
	}
}
