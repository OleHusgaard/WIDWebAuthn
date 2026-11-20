package dk.sparre.market.account.webauthn;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CredentialManager {
	private static final int CREDENTIAL_ID_BYTES = 32;
	private static final int GCM_IV_LENGTH = 12;
	private static final int GCM_TAG_BITS = 128;

	private static final Base64.Encoder B64URL_ENC = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

	private final SecretKey masterAesKey;
	private final SecureRandom secureRandom = new SecureRandom();

	/**
	 * @param aes256KeyBytes 32-byte (256-bit) master key used to encrypt private
	 *                       keys at rest.
	 */
	public CredentialManager(SecretKey aes256Key) {
		Objects.requireNonNull(aes256Key, "aes256Key must not be null");
		this.masterAesKey = aes256Key;
	}

	/**
	 * Generates a new ES256 (secp256r1) key pair and credential ID, encrypts the
	 * private key, and inserts the row into WEBAUTHNCREDENTIALS.
	 */
	public Credential createAndStore(Connection conn, String rpId, byte[] userHandle)
			throws GeneralSecurityException, SQLException {
		Objects.requireNonNull(conn, "conn must not be null");
		Objects.requireNonNull(rpId, "rpId must not be null");
		Objects.requireNonNull(userHandle, "userHandle must not be null");

		rpId = rpId.trim().toLowerCase(Locale.ROOT);
		if (rpId.isEmpty())
			throw new IllegalArgumentException("rpId must not be empty");

		byte[] credIdBytes = new byte[CREDENTIAL_ID_BYTES];
		secureRandom.nextBytes(credIdBytes);
		String credIdB64Url = B64URL_ENC.encodeToString(credIdBytes);
		String userHandleB64Url = B64URL_ENC.encodeToString(userHandle);

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		keyGen.initialize(new ECGenParameterSpec("secp256r1"), secureRandom);
		KeyPair keyPair = keyGen.generateKeyPair();
		ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
		ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
		String encryptedPrivateKey = encryptPrivateKey(privKey.getEncoded(), rpId, credIdB64Url);

		long generatedId;
		try (PreparedStatement ps = conn.prepareStatement(
				"INSERT INTO WEBAUTHNCREDENTIALS (CREDENTIALID, RPID, USERHANDLE, PRIVATEKEY, SIGNCOUNT)	VALUES (?, ?, ?, ?, 0)",
				Statement.RETURN_GENERATED_KEYS)) {
			ps.setString(1, credIdB64Url);
			ps.setString(2, rpId);
			ps.setString(3, userHandleB64Url);
			ps.setString(4, encryptedPrivateKey);
			ps.executeUpdate();

			try (ResultSet rs = ps.getGeneratedKeys()) {
				if (!rs.next())
					throw new SQLException("Failed to retrieve generated ID from WEBAUTHNCREDENTIALS");
				generatedId = rs.getLong(1);
			}
		}

		return new Credential(generatedId, credIdBytes, rpId, userHandle, privKey, pubKey);
	}

	/**
	 * Loads a credential from the database.
	 */
	public Credential loadCredential(Connection conn, int id) throws GeneralSecurityException, SQLException {
		Objects.requireNonNull(conn, "conn must not be null");

		try (PreparedStatement ps = conn.prepareStatement(
				"SELECT RPID, CREDENTIALID, USERHANDLE, PRIVATEKEY FROM WEBAUTHNCREDENTIALS WHERE ID = ?")) {
			ps.setInt(1, id);

			try (ResultSet rs = ps.executeQuery()) {
				if (!rs.next())
					throw new SQLException("No credential found in WEBAUTHNCREDENTIALS with ID=" + id);

				String credIdB64Url = rs.getString("CREDENTIALID");
				String rpId = rs.getString("RPID");
				String userHandleB64Url = rs.getString("USERHANDLE");
				byte[] pkcs8Bytes = decryptPrivateKey(rs.getString("PRIVATEKEY"), rpId, credIdB64Url);
				KeyFactory kf = KeyFactory.getInstance("EC");
				ECPrivateKey privKey = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));

				return new Credential(id, B64URL_DEC.decode(credIdB64Url), rpId, B64URL_DEC.decode(userHandleB64Url),
						privKey, null);
			}
		}
	}

	/**
	 * Atomically increments SIGNCOUNT in the database.
	 * 
	 * @returns The updated counter value.
	 */
	public long incrementSignCount(Connection conn, long dbId) throws SQLException {
		Objects.requireNonNull(conn, "conn must not be null");

		try (PreparedStatement ps = conn
				.prepareStatement("UPDATE WEBAUTHNCREDENTIALS SET SIGNCOUNT = SIGNCOUNT + 1 WHERE ID = ?")) {
			ps.setLong(1, dbId);
			if (ps.executeUpdate() == 0)
				throw new SQLException("No credential found in WEBAUTHNCREDENTIALS with ID=" + dbId);
		}

		try (PreparedStatement ps = conn.prepareStatement("SELECT SIGNCOUNT FROM WEBAUTHNCREDENTIALS WHERE ID = ?")) {
			ps.setLong(1, dbId);
			try (ResultSet rs = ps.executeQuery()) {
				if (rs.next())
					return rs.getLong(1);
				throw new SQLException("Failed to read updated SIGNCOUNT for ID=" + dbId);
			}
		}
	}

	private String encryptPrivateKey(byte[] pkcs8Bytes, String rpId, String credIdB64Url)
			throws GeneralSecurityException {
		byte[] iv = new byte[GCM_IV_LENGTH];
		secureRandom.nextBytes(iv);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, masterAesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
		cipher.updateAAD(buildAad(rpId, credIdB64Url));

		byte[] ciphertext = cipher.doFinal(pkcs8Bytes);

		ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
		buffer.put(iv);
		buffer.put(ciphertext);
		return B64URL_ENC.encodeToString(buffer.array());
	}

	private byte[] decryptPrivateKey(String encryptedB64Url, String rpId, String credIdB64Url)
			throws GeneralSecurityException {
		byte[] packed = B64URL_DEC.decode(encryptedB64Url);
		if (packed.length <= GCM_IV_LENGTH)
			throw new GeneralSecurityException("Encrypted private key payload is truncated");

		byte[] iv = Arrays.copyOfRange(packed, 0, GCM_IV_LENGTH);
		byte[] ciphertext = Arrays.copyOfRange(packed, GCM_IV_LENGTH, packed.length);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, masterAesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
		cipher.updateAAD(buildAad(rpId, credIdB64Url));

		return cipher.doFinal(ciphertext);
	}

	private static byte[] buildAad(String rpId, String credIdB64Url) {
		return (rpId + ":" + credIdB64Url).getBytes(StandardCharsets.UTF_8);
	}
}