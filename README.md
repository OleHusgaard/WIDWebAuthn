# WIDWebAuthn

A lightweight, pure-JDK 21 [WebAuthn](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/) / Passkey client for automated passwordless authentication against [WhiskyInvestDirect](https://www.whiskyinvestdirect.com).

Built using only standard Java 21 APIs — no third-party WebAuthn, CBOR, or JSON libraries required.

This software is not endorsed by or in any way connected with WhiskyInvestDirect Ltd.

It was written because the author needed a quick fix for the higher security on their new home page introduced on November 16th 2026 without introducing a lot of dependencies. Since WebAuthn is a standard this software can probably easily be adapted to other web sites supporting passkeys. 

---

## Features
- **Pure-JDK Cryptography & Wire Encoding:** Currently limited to generating and using ES256 key pairs.
- **Encrypted Key Storage:** Encrypts private keys at rest using AES-256-GCM and a PBKDF2-derived master key.

---

## Prerequisites

- **Java 21** or newer
- **MariaDB** (or MySQL-compatible database)
- **MariaDB Connector/J** (`mariadb-java-client` JAR on your classpath)
- **An account at WhiskyInvestDirect**

---

## Database Setup

Create the `WEBAUTHNCREDENTIALS` table to store credential metadata, encrypted private keys, and signature counters:

```sql
CREATE TABLE IF NOT EXISTS WEBAUTHNCREDENTIALS (
  ID SERIAL,
  CREDENTIALID VARCHAR(2048) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  RPID VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  USERHANDLE VARCHAR(100) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  PRIVATEKEY VARCHAR(8192) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  SIGNCOUNT BIGINT UNSIGNED NOT NULL DEFAULT 0,

  PRIMARY KEY (ID),
  UNIQUE KEY (RPID, CREDENTIALID)
);
```

---

## Code setup

Edit the Secrets.java file to suit your environment. You need to change the six constants in the beginning of the file:
1. **DB_URL** The URL for the database.
2. **DB_USERNAME** The user name for the database.
3. **DB_PASSWORD** The user's password for the database.
4. **ACCOUNT_NAME** The email you use for your account at WhiskyInvestDirect.
5. **PASSWORD** The password you use to log in at WhiskyInvestDirect.
6. **SALT** A salt used in combination with a pin code entered by the user to derive the key used for encrypting the private keys in the database.

DB_PASSWORD and PASSWORD are secrets that should never be hard coded in a source file. Use a proper secrets manager to handle these in a production system. The only secrets this software handles properly are the WebAuthn private keys. But it makes testing easier.

SALT can be hard coded in a source file, as it is only usable in connection with a pin code entered by the user, but you should create your own salt and keep it confidential.

---

## The pin code

This should be handled as the password needed for using the passkeys. Keep it secret. You will be asked for it the first time your system tries to create or use a passkey.

---

## How to use

Run class SetupPasskey. It will use your credentials in class Secrets to authenticate at WhiskyInvestDirect. Then you will get a code on your mobile phone that you should enter. Then the program creates a passkey, stores it in the database, and registers this passkey at WhiskyInvestDirect. To confirm this security-sensitive operation you will again get a code on your mobile phone that you should enter.

---

## How to test

Edit constant CREDENTIAL_DATABASE_ID in class PassKeyAuthenticationTest to be the primary key in the database of the passkey you want to use for authentication. Then run PassKeyAuthenticationTest. You will not be asked for a password, only your pin code to unlock the passkeys. The program will output some ugly JSON from WhiskyInvestDirect which includes your phone number to prove it could authenticate.
