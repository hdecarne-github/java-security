/*
 * Copyright (c) 2018-2019 Holger de Carne and contributors, All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package de.carne.security.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import de.carne.boot.logging.Log;
import de.carne.io.IOUtil;
import de.carne.security.secret.ByteSecret;
import de.carne.security.util.CipherUtil;
import de.carne.security.util.Destroyables;
import de.carne.security.util.Randomness;
import de.carne.security.util.SafeByteArrayOutputStream;

/**
 * AES based {@linkplain StorableCoder} supporting multiple key lengths.
 */
final class AESCoder extends StorableCoder {

	private static final Log LOG = new Log();

	private static final String KEY_FACTORY_ALG = "PBKDF2WithHmacSHA256";
	private static final String CIPHER_ALG = "AES/GCM/NoPadding";
	private static final int SALT_LENGTH = 8;
	private static final int IV_LENGTH = 12;
	private static final int GCM_TLEN = 128;

	public static final String KEY_ALG = "AES";

	private final SecretKeySpec secretKeySpec;
	private final byte[] salt;

	private AESCoder(StorableCoderId id, SecretKeySpec secretKeySpec, byte[] salt) {
		super(id);
		this.secretKeySpec = secretKeySpec;
		this.salt = salt;
	}

	static AESCoder newCoder(StorableCoderId id) throws GeneralSecurityException {
		LOG.info("Generating new {0} coder...", id);

		int keyLength;

		switch (id) {
		case AES128:
			keyLength = 128;
			break;
		case AES256:
			keyLength = 256;
			break;
		default:
			throw new IllegalArgumentException("Unexpected coder id: " + id);
		}

		byte[] salt = new byte[SALT_LENGTH];

		Randomness.get().nextBytes(salt);

		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KEY_FACTORY_ALG);
		KeySpec keySpec = new PBEKeySpec(null, salt, 65536, keyLength);
		SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
		byte[] encodedSecretKey;

		try {
			encodedSecretKey = Objects.requireNonNull(secretKey.getEncoded());
		} finally {
			Destroyables.safeDestroy(secretKey);
		}

		SecretKeySpec secretKeySpec = new SecretKeySpec(encodedSecretKey, KEY_ALG);

		return new AESCoder(id, secretKeySpec, salt);
	}

	static AESCoder loadCoder(StorableCoderId id, byte[] secret, int secretOff, int secretLen)
			throws GeneralSecurityException {
		LOG.info("Loading {0} coder...", id);

		int headerLength = validateSecretHeader(id, secret, secretOff, secretLen);
		int extendedHeaderLength = headerLength + SALT_LENGTH;

		if (secretLen < extendedHeaderLength) {
			throw new IllegalArgumentException("Invalid AES coder secret");
		}

		byte[] salt = new byte[SALT_LENGTH];

		System.arraycopy(secret, headerLength, salt, 0, SALT_LENGTH);
		SecretKeySpec secretKeySpec = new SecretKeySpec(secret, secretOff + extendedHeaderLength,
				secretLen - extendedHeaderLength, KEY_ALG);
		return new AESCoder(id, secretKeySpec, salt);
	}

	@Override
	public ByteSecret store() throws GeneralSecurityException {
		ByteSecret secret;
		try (SafeByteArrayOutputStream secretBuffer = new SafeByteArrayOutputStream(0)) {
			storeSecretHeader(secretBuffer);
			secretBuffer.write(this.salt);
			secretBuffer.write(this.secretKeySpec.getEncoded());
			secret = ByteSecret.wrap(secretBuffer.getBytes());
		}
		return secret;
	}

	@Override
	public int encrypt(InputStream in, OutputStream out) throws IOException, GeneralSecurityException {
		byte[] iv = new byte[IV_LENGTH];

		Randomness.get().nextBytes(iv);
		out.write(iv);

		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TLEN, iv);
		Cipher cipher = Cipher.getInstance(CIPHER_ALG);

		cipher.init(Cipher.ENCRYPT_MODE, this.secretKeySpec, gcmParameterSpec);
		return CipherUtil.stream(cipher, in, out);
	}

	@Override
	public int decrypt(InputStream in, OutputStream out) throws IOException, GeneralSecurityException {
		byte[] iv = new byte[IV_LENGTH];

		IOUtil.readEager(in, iv);

		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TLEN, iv);
		Cipher cipher = Cipher.getInstance(CIPHER_ALG);

		cipher.init(Cipher.DECRYPT_MODE, this.secretKeySpec, gcmParameterSpec);
		return CipherUtil.stream(cipher, in, out);
	}

	@Override
	public void close() {
		Arrays.fill(this.salt, (byte) 0);
		Destroyables.safeDestroy(this.secretKeySpec);
	}

}
