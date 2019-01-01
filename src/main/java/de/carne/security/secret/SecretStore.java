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

import org.eclipse.jdt.annotation.Nullable;

/**
 * Base class for all kind of {@linkplain SecretStore}s.
 */
abstract class SecretStore {

	public abstract boolean isAvailable() throws IOException;

	public abstract boolean hasSecret(String id) throws IOException;

	public abstract void deleteSecret(String id) throws IOException;

	public abstract byte @Nullable [] getSecret(String id) throws IOException;

	public abstract void setSecret(String id, byte[] secret) throws IOException;

	public final Cipher getCipher(String id) throws IOException, GeneralSecurityException {
		byte @Nullable [] secret = getSecret(id);

		if (secret == null) {
			secret = generateSecret();
			setSecret(id, secret);
		}

		Cipher cipher;

		try (ByteSecret cipherSecret = ByteSecret.wrap(secret)) {
			cipher = getCipherInstance(secret);
		}
		return cipher;
	}

	@Override
	public final String toString() {
		return getClass().getSimpleName();
	}

	private byte[] generateSecret() throws GeneralSecurityException {
		return AESCipher
				.generateSecret(javax.crypto.Cipher.getMaxAllowedKeyLength(AESCipher.KEY_ALG) >= 256 ? 256 : 128);
	}

	@SuppressWarnings("squid:S1301")
	private Cipher getCipherInstance(byte[] secret) {
		if (secret.length == 0) {
			throw new IllegalArgumentException("Invalid cipher secret");
		}

		Cipher cipher;

		switch (secret[0]) {
		case AESCipher.ID:
			cipher = AESCipher.getInstance(secret);
			break;
		default:
			throw new IllegalArgumentException("Unrecognized cipher secret: " + secret[0]);
		}
		return cipher;
	}

}
