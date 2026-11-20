package dk.sparre.market.account.webauthn;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

public record Credential(long dbId, byte[] credentialId, String rpId, byte[] userHandle, ECPrivateKey privateKey,
		ECPublicKey publicKey // Present at creation; null when loaded from DB
) {
	private static final Base64.Encoder B64URL_ENC = Base64.getUrlEncoder().withoutPadding();
	private static final byte ASSERTION_FLAGS = 0x05; // UP (0x01) | UV (0x04)

	/**
	 * Compact constructor enforcing defensive copies of mutable byte arrays.
	 */
	public Credential {
		credentialId = Arrays.copyOf(credentialId, credentialId.length);
		userHandle = Arrays.copyOf(userHandle, userHandle.length);
	}

	@Override
	public byte[] credentialId() {
		return Arrays.copyOf(credentialId, credentialId.length);
	}

	@Override
	public byte[] userHandle() {
		return Arrays.copyOf(userHandle, userHandle.length);
	}

	/**
	 * Calculates the unpadded Base64URL representation of credentialId on demand.
	 */
	public String credentialIdBase64Url() {
		return B64URL_ENC.encodeToString(credentialId);
	}

	/**
	 * Calculates the unpadded Base64URL representation of userHandle on demand.
	 */
	public String userHandleBase64Url() {
		return B64URL_ENC.encodeToString(userHandle);
	}

	/**
	 * Signs a WebAuthn login challenge with this credential's ECPrivateKey and
	 * formats the JSON payload expected by POST /signin/passkey.
	 */
	public String buildLoginRequestJson(String origin, String challengeId, String challengeB64Url, long nextSignCount)
			throws GeneralSecurityException {
		Objects.requireNonNull(origin, "origin must not be null");
		Objects.requireNonNull(challengeId, "challengeId must not be null");
		Objects.requireNonNull(challengeB64Url, "challengeB64Url must not be null");

		// 1. Build clientDataJSON
		String clientDataJson = "{\"type\":\"webauthn.get\",\"challenge\":\"" + escapeJson(challengeB64Url)
				+ "\",\"origin\":\"" + escapeJson(origin) + "\",\"crossOrigin\":false}";
		byte[] clientDataBytes = clientDataJson.getBytes(StandardCharsets.UTF_8);

		// 2. Build 37-byte authenticatorData: [32-byte rpIdHash] || [1-byte flags
		// (0x05)] || [4-byte signCount]
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] rpIdHash = sha256.digest(rpId.getBytes(StandardCharsets.UTF_8));

		ByteBuffer authDataBuf = ByteBuffer.allocate(37);
		authDataBuf.put(rpIdHash);
		authDataBuf.put(ASSERTION_FLAGS);
		authDataBuf.putInt((int) nextSignCount);
		byte[] authData = authDataBuf.array();

		// 3. Sign (authenticatorData || SHA-256(clientDataJSON)) using ES256
		// (DER-encoded ECDSA)
		Signature signer = Signature.getInstance("SHA256withECDSA");
		signer.initSign(privateKey);
		signer.update(authData);
		signer.update(sha256.digest(clientDataBytes));

		String credIdB64Url = credentialIdBase64Url();
		return """
				{
				  "challengeId": "%s",
				  "response": {
				    "id": "%s",
				    "rawId": "%s",
				    "type": "public-key",
				    "authenticatorAttachment": "platform",
				    "response": {
				      "authenticatorData": "%s",
				      "clientDataJSON": "%s",
				      "signature": "%s",
				      "userHandle": "%s"
				    },
				    "clientExtensionResults": {}
				  }
				}
				""".formatted(escapeJson(challengeId), credIdB64Url, credIdB64Url, B64URL_ENC.encodeToString(authData),
				B64URL_ENC.encodeToString(clientDataBytes), B64URL_ENC.encodeToString(signer.sign()),
				B64URL_ENC.encodeToString(userHandle));
	}

	/**
	 * Extracts the fixed 32-byte unsigned X coordinate for CBOR COSE_Key
	 * registration.
	 */
	public byte[] getPublicKeyX() {
		if (publicKey == null)
			throw new IllegalStateException("Public key is only available immediately after creation");
		return toFixed32Bytes(publicKey.getW().getAffineX());
	}

	/**
	 * Extracts the fixed 32-byte unsigned Y coordinate for CBOR COSE_Key
	 * registration.
	 */
	public byte[] getPublicKeyY() {
		if (publicKey == null)
			throw new IllegalStateException("Public key is only available immediately after creation");
		return toFixed32Bytes(publicKey.getW().getAffineY());
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (!(o instanceof Credential other))
			return false;
		return dbId == other.dbId && Arrays.equals(credentialId, other.credentialId) && rpId.equals(other.rpId)
				&& Arrays.equals(userHandle, other.userHandle) && privateKey.equals(other.privateKey)
				&& java.util.Objects.equals(publicKey, other.publicKey);
	}

	@Override
	public int hashCode() {
		int result = java.util.Objects.hash(dbId, rpId, privateKey, publicKey);
		result = 31 * result + Arrays.hashCode(credentialId);
		result = 31 * result + Arrays.hashCode(userHandle);
		return result;
	}

	@Override
	public String toString() {
		return "Credential[" + "dbId=" + dbId + ", credentialId=" + credentialIdBase64Url() + ", rpId='" + rpId + '\''
				+ ", userHandle=" + userHandleBase64Url() + ", privateKey=[REDACTED]" + ", hasPublicKey="
				+ (publicKey != null) + ']';
	}

	private static byte[] toFixed32Bytes(BigInteger coordinate) {
		byte[] raw = coordinate.toByteArray();
		byte[] fixed = new byte[32];
		if (raw.length == 32)
			return raw;
		if (raw.length == 33 && raw[0] == 0x00) {
			System.arraycopy(raw, 1, fixed, 0, 32);
		} else if (raw.length < 32) {
			System.arraycopy(raw, 0, fixed, 32 - raw.length, raw.length);
		} else {
			throw new IllegalArgumentException("Invalid P-256 coordinate length: " + raw.length);
		}
		return fixed;
	}

	private static String escapeJson(String value) {
		return value.replace("\\", "\\\\").replace("\"", "\\\"");
	}
}