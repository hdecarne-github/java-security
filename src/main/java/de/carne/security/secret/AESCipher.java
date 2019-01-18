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
package de.carne.security.secret;

import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import de.carne.boot.logging.Log;
import de.carne.security.util.Destroyables;
import de.carne.security.util.Randomness;

/**
 * 256 bit AES cipher.
 */
class AESCipher extends Cipher {

	private static final Log LOG = new Log();

	private static final String KEY_FACTORY_ALG = "PBKDF2WithHmacSHA256";
	private static final String CIPHER_ALG = "AES/GCM/NoPadding";
	private static final int SALT_LENGTH = 8;
	private static final int IV_LENGTH = 12;
	private static final int GCM_TLEN = 128;

	public static final String KEY_ALG = "AES";

	public static final byte ID = 1;

	private final SecretKeySpec secretKeySpec;
	private final byte[] salt;

	AESCipher(SecretKeySpec secretKeySpec, byte[] salt, int saltOffset, int saltLength) {
		this.secretKeySpec = secretKeySpec;
		this.salt = new byte[saltLength];
		System.arraycopy(salt, saltOffset, this.salt, 0, saltLength);
	}

	public static byte[] generateSecret(int keyLength) throws GeneralSecurityException {
		LOG.info("Generating AES-{0} cipher secret...", keyLength);

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

		byte[] secret = new byte[1 + salt.length + encodedSecretKey.length];

		secret[0] = ID;
		System.arraycopy(salt, 0, secret, 1, salt.length);
		System.arraycopy(encodedSecretKey, 0, secret, 1 + salt.length, encodedSecretKey.length);
		Arrays.fill(salt, (byte) 0);
		Arrays.fill(encodedSecretKey, (byte) 0);
		return secret;
	}

	public static AESCipher getInstance(byte[] secret) {
		if (secret.length < 1 + SALT_LENGTH || secret[0] != ID) {
			throw new IllegalArgumentException("Invalid AES cipher secret");
		}

		SecretKeySpec secretKeySpec = new SecretKeySpec(secret, 1 + SALT_LENGTH, secret.length - 1 - SALT_LENGTH,
				KEY_ALG);

		return new AESCipher(secretKeySpec, secret, 1, SALT_LENGTH);
	}

	@Override
	public byte[] encrypt(byte[] plain) throws GeneralSecurityException {
		byte[] iv = new byte[IV_LENGTH];

		Randomness.get().nextBytes(iv);

		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TLEN, iv);
		javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(CIPHER_ALG);

		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, this.secretKeySpec, gcmParameterSpec);

		byte[] encryptedData = cipher.doFinal(plain);
		byte[] encrypted = new byte[iv.length + encryptedData.length];

		System.arraycopy(iv, 0, encrypted, 0, iv.length);
		Arrays.fill(iv, (byte) 0);
		System.arraycopy(encryptedData, 0, encrypted, iv.length, encryptedData.length);
		Arrays.fill(encryptedData, (byte) 0);
		return encrypted;
	}

	@Override
	public byte[] decrypt(byte[] encrypted) throws GeneralSecurityException {
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TLEN, encrypted, 0, IV_LENGTH);
		javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(CIPHER_ALG);

		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, this.secretKeySpec, gcmParameterSpec);
		return Objects.requireNonNull(cipher.doFinal(encrypted, IV_LENGTH, encrypted.length - IV_LENGTH));
	}

	@Override
	public void close() {
		Arrays.fill(this.salt, (byte) 0);
		Destroyables.safeDestroy(this.secretKeySpec);
	}

}
