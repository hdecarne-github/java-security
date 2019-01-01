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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Consumer;

import de.carne.boot.logging.Log;

/**
 * The {@code SecureStorage} class provides functions to handle sensitive data in a secure way.
 * <p>
 * During creation of a new {@code SecureStorage} instance a random encryption secret is created and stored only
 * accessible to the current process' user. This encryption secret is then used to secure any kind of sensitive data.
 * </p>
 */
public final class SecureStorage {

	private static final Log LOG = new Log();

	private static final SecretStore[] SECRET_STORES = { new GenericSecretStore(), new MacOSSecretStore(),
			new WindowsSecretStore() };

	private final SecretStore secretStore;
	private final String id;

	private SecureStorage(SecretStore secretStore, String id) {
		this.secretStore = secretStore;
		this.id = id;

		LOG.info("Created {0}", this);
	}

	/**
	 * Creates a new {@linkplain SecureStorage} instance for a given id.
	 * <p>
	 * The submitted id is used to uniquely identify the encryption secret to use. Unless {@linkplain #delete()} is
	 * called for the created instance a subsequent call with the same id will create an instance with the same
	 * encryption secret.
	 * </p>
	 *
	 * @param id the id of the {@linkplain SecureStorage} instance to create.
	 * @return the created {@linkplain SecureStorage} instance.
	 * @throws IOException if an I/O error occurs during creation.
	 */
	public static SecureStorage create(String id) throws IOException {
		SecretStore availableSecretStore = null;
		SecretStore matchingSecretStore = null;

		for (SecretStore secretStore : SECRET_STORES) {
			if (secretStore.isAvailable()) {
				availableSecretStore = secretStore;
				if (secretStore.hasSecret(id)) {
					matchingSecretStore = secretStore;
				}
			}
		}

		Objects.requireNonNull(availableSecretStore);

		return new SecureStorage((matchingSecretStore != null ? matchingSecretStore : availableSecretStore), id);
	}

	/**
	 * Encrypt a given byte secret.
	 *
	 * @param secret the byte secret to encrypt.
	 * @return the encrypted byte secret.
	 * @throws IOException if an I/O error occurs during encryption.
	 * @see #decryptBytes(byte[], Consumer)
	 */
	public byte[] encryptBytes(ByteSecret secret) throws IOException {
		byte[] encrypted;

		try (Cipher cipher = this.secretStore.getCipher(this.id)) {
			encrypted = secret.apply(cipher::encrypt);
		} catch (GeneralSecurityException e) {
			throw new IOException(e.getLocalizedMessage(), e);
		}
		return encrypted;
	}

	/**
	 * Encrypt a given byte secret and base64 encode the encrypted bytes.
	 *
	 * @param secret the byte secret to encrypt.
	 * @return the base64 encoded encrypted byte secret.
	 * @throws IOException if an I/O error occurs during encryption.
	 * @see #decryptBytesBase64(String, Consumer)
	 */
	public String encryptBytesBase64(ByteSecret secret) throws IOException {
		return Base64.getEncoder().encodeToString(encryptBytes(secret));
	}

	/**
	 * Decrypt a previously encrypted byte secret.
	 *
	 * @param encrypted the encrypted byte secret.
	 * @param consumer the {@linkplain Consumer} to invoke with the decrypted byte secret.
	 * @throws IOException if an I/O error occurs during decryption.
	 * @see #encryptBytes(ByteSecret)
	 */
	public void decryptBytes(byte[] encrypted, Consumer<byte[]> consumer) throws IOException {
		try (Cipher cipher = this.secretStore.getCipher(this.id);
				ByteSecret decrypted = ByteSecret.wrap(cipher.decrypt(encrypted))) {
			decrypted.accept(consumer);
		} catch (GeneralSecurityException e) {
			throw new IOException(e.getLocalizedMessage(), e);
		}
	}

	/**
	 * Decrypt a previously encrypted and base64 encoded byte secret.
	 *
	 * @param encrypted the encrypted and base64 encoded byte secret.
	 * @param consumer the {@linkplain Consumer} to invoke with the decrypted byte secret.
	 * @throws IOException if an I/O error occurs during decryption.
	 * @see #encryptBytesBase64(ByteSecret)
	 */
	public void decryptBytesBase64(String encrypted, Consumer<byte[]> consumer) throws IOException {
		decryptBytes(Base64.getDecoder().decode(encrypted), consumer);
	}

	/**
	 * Encrypt a given char secret.
	 *
	 * @param secret the char secret to encrypt.
	 * @return the encrypted char secret.
	 * @throws IOException if an I/O error occurs during encryption.
	 * @see #decryptChars(byte[], Consumer)
	 */
	public byte[] encryptChars(CharSecret secret) throws IOException {
		byte[] encrypted;

		try (ByteSecret byteSecret = secret.apply(SecureStorage::encodeChars)) {
			encrypted = encryptBytes(byteSecret);
		} catch (GeneralSecurityException e) {
			throw new IOException(e.getLocalizedMessage(), e);
		}
		return encrypted;
	}

	private static ByteSecret encodeChars(char[] plainChars) {
		byte[] plainBytes = new byte[2 * plainChars.length];

		for (int plainCharIndex = 0; plainCharIndex < plainChars.length; plainCharIndex++) {
			plainBytes[2 * plainCharIndex] = (byte) (plainChars[plainCharIndex] & 0xff);
			plainBytes[2 * plainCharIndex + 1] = (byte) ((plainChars[plainCharIndex] & 0xff00) >> 8);
		}
		return ByteSecret.wrap(plainBytes);
	}

	/**
	 * Encrypt a given char secret and base64 encode the encrypted bytes.
	 *
	 * @param secret the char secret to encrypt.
	 * @return the encrypted and base64 encoded char secret.
	 * @throws IOException if an I/O error occurs during encryption.
	 * @see #decryptCharsBase64(String, Consumer)
	 */
	public String encryptCharsBase64(CharSecret secret) throws IOException {
		return Base64.getEncoder().encodeToString(encryptChars(secret));
	}

	/**
	 * Decrypt a previously encrypted char secret.
	 *
	 * @param encrypted the encrypted char secret.
	 * @param consumer the {@linkplain Consumer} to invoke with the decrypted char secret.
	 * @throws IOException if an I/O error occurs during decryption.
	 * @see #encryptChars(CharSecret)
	 */
	public void decryptChars(byte[] encrypted, Consumer<char[]> consumer) throws IOException {
		decryptBytes(encrypted, plainBytes -> {
			try (CharSecret charSecret = decodeChars(plainBytes)) {
				charSecret.accept(consumer);
			}
		});
	}

	private static CharSecret decodeChars(byte[] plainBytes) {
		char[] plainChars = new char[plainBytes.length / 2];

		for (int plainCharIndex = 0; plainCharIndex < plainChars.length; plainCharIndex++) {
			plainChars[plainCharIndex] = (char) ((plainBytes[2 * plainCharIndex] & 0xff)
					| ((plainBytes[2 * plainCharIndex + 1] & 0xff) << 8));
		}
		return CharSecret.wrap(plainChars);
	}

	/**
	 * Decrypt a previously encrypted and base64 encoded char secret.
	 *
	 * @param encrypted the encrypted and base64 encoded char secret.
	 * @param consumer the {@linkplain Consumer} to invoke with the decrypted char secret.
	 * @throws IOException if an I/O error occurs during decryption.
	 * @see #encryptCharsBase64(CharSecret)
	 */
	public void decryptCharsBase64(String encrypted, Consumer<char[]> consumer) throws IOException {
		decryptChars(Base64.getDecoder().decode(encrypted), consumer);
	}

	/**
	 * Delete the encryption key of this {@linkplain SecureStorage} instance.
	 * <p>
	 * Deleting the encryption key makes any data previously encrypted vie this key inaccessible.
	 * </p>
	 *
	 * @throws IOException if an I/O error occurs during deletion.
	 */
	public void delete() throws IOException {
		this.secretStore.deleteSecret(this.id);
	}

	@Override
	public String toString() {
		return "SecureStorage[" + this.secretStore + ":" + this.id + "]";
	}

}
