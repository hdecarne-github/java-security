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
package de.carne.security.test.secret;

import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import de.carne.security.secret.ByteSecret;
import de.carne.security.secret.CharSecret;
import de.carne.security.secret.SecureStorage;
import de.carne.test.extension.TempPath;
import de.carne.test.extension.TempPathParameterResolver;

/**
 * Test {@linkplain SecureStorage} class.
 */
@ExtendWith(TempPathParameterResolver.class)
class SecureStorageTest {

	@BeforeAll
	static void setUserHomeToTempPath(TempPath tempPath) {
		System.setProperty("user.home", tempPath.get().toString());
	}

	private static final String TEST_PASSWORD = "AVerySecretPassword4Testing";

	@Test
	void testByteSecureStorage() throws IOException {
		SecureStorage newStorage = SecureStorage.create(SecureStorageTest.class.getName());
		final byte[] token = TEST_PASSWORD.getBytes();

		try (ByteSecret tokenSecret = ByteSecret.wrap(token)) {
			// Test encryption and decryption
			byte[] encryptedToken = newStorage.encryptBytes(tokenSecret);

			newStorage.decryptBytes(encryptedToken,
					decryptedToken -> Assertions.assertArrayEquals(token, decryptedToken));

			// Test decryption with a recreated storage instance
			SecureStorage oldStorage = SecureStorage.create(SecureStorageTest.class.getName());

			oldStorage.decryptBytes(encryptedToken,
					decryptedToken -> Assertions.assertArrayEquals(token, decryptedToken));

			// Test whether decryption no longer works after deletion of storage instance
			oldStorage.delete();

			Assertions.assertThrows(IOException.class, () -> newStorage.decryptBytes(encryptedToken,
					decryptedToken -> Assertions.assertFalse(Arrays.equals(token, decryptedToken))));
		}

		// Test whether password is cleared by now
		Assertions.assertArrayEquals(new byte[token.length], token);

		newStorage.delete();
	}

	@Test
	void testCharSecureStorage() throws IOException {
		SecureStorage newStorage = SecureStorage.create(SecureStorageTest.class.getName());
		final char[] password = TEST_PASSWORD.toCharArray();

		try (CharSecret passwordSecret = CharSecret.wrap(password)) {
			// Test encryption and decryption
			byte[] encryptedPassword = newStorage.encryptChars(passwordSecret);

			newStorage.decryptChars(encryptedPassword,
					decryptedPassword -> Assertions.assertArrayEquals(password, decryptedPassword));

			// Test decryption with a recreated storage instance
			SecureStorage oldStorage = SecureStorage.create(SecureStorageTest.class.getName());

			oldStorage.decryptChars(encryptedPassword,
					decryptedPassword -> Assertions.assertArrayEquals(password, decryptedPassword));

			// Test whether decryption no longer works after deletion of storage instance
			oldStorage.delete();

			Assertions.assertThrows(IOException.class, () -> newStorage.decryptChars(encryptedPassword,
					decryptedPassword -> Assertions.assertFalse(Arrays.equals(password, decryptedPassword))));
		}

		// Test whether password is cleared by now
		Assertions.assertArrayEquals(new char[password.length], password);

		newStorage.delete();
	}

	@Test
	void testBase64SecureStorage() throws IOException {
		SecureStorage storage = SecureStorage.create(SecureStorageTest.class.getName());
		final byte[] token = TEST_PASSWORD.getBytes();

		try (ByteSecret tokenSecret = ByteSecret.wrap(token)) {
			// Test encryption and decryption of bytes
			String encryptedToken = storage.encryptBytesBase64(tokenSecret);

			storage.decryptBytesBase64(encryptedToken,
					decryptedToken -> Assertions.assertArrayEquals(token, decryptedToken));
		}

		final char[] password = TEST_PASSWORD.toCharArray();

		try (CharSecret passwordSecret = CharSecret.wrap(password)) {
			// Test encryption and decryption of chars
			String encryptedPassword = storage.encryptCharsBase64(passwordSecret);

			storage.decryptCharsBase64(encryptedPassword,
					decryptedPassword -> Assertions.assertArrayEquals(password, decryptedPassword));
		}
		storage.delete();
	}

}
