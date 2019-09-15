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

import java.security.GeneralSecurityException;

import de.carne.security.secret.ByteSecret;
import de.carne.security.util.SafeByteArrayOutputStream;

/**
 * Base class for {@linkplain Coder} implementation based upon a secret that can be retrieved and stored locally.
 */
public abstract class StorableCoder extends Coder {

	private static final int SECRET_HEADER_LENGTH = 4;

	private final StorableCoderId id;

	protected StorableCoder(StorableCoderId id) {
		this.id = id;
	}

	/**
	 * Gets the default {@linkplain StorableCoderId} for the running platform.
	 *
	 * @return the default {@linkplain StorableCoderId} for the running platform.
	 */
	public static StorableCoderId defaultCoder() {
		return AESCoder.getDefaultCoder();
	}

	/**
	 * Load {@linkplain StorableCoder} instance from a stored secret.
	 *
	 * @param secret the secret to load the {@linkplain StorableCoder} instance from.
	 * @return the loaded {@linkplain StorableCoder} instance.
	 * @throws GeneralSecurityException if a load error occurs.
	 */
	public static final StorableCoder load(ByteSecret secret) throws GeneralSecurityException {
		return secret.apply(plain -> {
			if (plain.length < SECRET_HEADER_LENGTH) {
				throw new GeneralSecurityException("Unexpected secret header length: " + plain.length);
			}

			int idOrdinal = (plain[3] << 24) | ((plain[2] & 0xff) << 16) | ((plain[1] & 0xff) << 8) | (plain[0] & 0xff);
			StorableCoderId[] ids = StorableCoderId.values();

			if (idOrdinal < 0 || ids.length <= idOrdinal) {
				throw new GeneralSecurityException("Unexpected coder id: " + idOrdinal);
			}

			StorableCoderId id = ids[idOrdinal];

			return id.loadCoder(secret);
		});
	}

	/**
	 * Validates the secret header during coder loading.
	 * <p>
	 * Called by the specific {@linkplain StorableCoder} instance to advance to it's specific secret data.
	 * </p>
	 *
	 * @param id the {@linkplain StorableCoderId} of the {@linkplain StorableCoder} instance to load.
	 * @param secret the secret data to load the coder {@linkplain StorableCoder} instance from.
	 * @param secretOff the offset to start reading.
	 * @param secretLen the maximum number of bytes to read.
	 * @return the size of the skipped header.
	 * @throws GeneralSecurityException if a load error occurs.
	 */
	protected static int validateSecretHeader(StorableCoderId id, byte[] secret, int secretOff, int secretLen)
			throws GeneralSecurityException {
		if (secretLen < SECRET_HEADER_LENGTH) {
			throw new GeneralSecurityException("Unexpected secret header length: " + secretLen);
		}

		int idOrdinal = (secret[secretOff + 3] << 24) | ((secret[secretOff + 2] & 0xff) << 16)
				| ((secret[secretOff + 1] & 0xff) << 8) | (secret[secretOff + 0] & 0xff);

		if (idOrdinal != id.ordinal()) {
			throw new GeneralSecurityException("Unexpected coder id: " + idOrdinal);
		}
		return SECRET_HEADER_LENGTH;
	}

	/**
	 * Stores the secret header.
	 *
	 * @param secretBuffer the buffer to store the secret into.
	 * @throws GeneralSecurityException if a store error occurs.
	 */
	protected void storeSecretHeader(SafeByteArrayOutputStream secretBuffer) throws GeneralSecurityException {
		int idOrdinal = this.id.ordinal();

		secretBuffer.write(new byte[] { (byte) (idOrdinal & 0xff), (byte) ((idOrdinal >> 8) & 0xff),
				(byte) ((idOrdinal >> 16) & 0xff), (byte) ((idOrdinal >> 24) & 0xff) });
	}

	/**
	 * Gets this {@linkplain StorableCoder} instance's secret.
	 *
	 * @return this {@linkplain StorableCoder} instance's secret.
	 * @throws GeneralSecurityException if an error occurs while accessing the secret.
	 */
	public abstract ByteSecret store() throws GeneralSecurityException;

	/**
	 * Gets this {@linkplain StorableCoder}'s id.
	 *
	 * @return this {@linkplain StorableCoder}'s id.
	 */
	public final StorableCoderId id() {
		return this.id;
	}

	@Override
	public String toString() {
		return this.id.toString();
	}

}
