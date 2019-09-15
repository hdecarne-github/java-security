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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import de.carne.security.util.SafeByteArrayOutputStream;

/**
 * Base class for all type of coders used for data encryption and decryption.
 */
@SuppressWarnings("squid:S1610")
public abstract class Coder implements AutoCloseable {

	/**
	 * Encrypt stream data.
	 *
	 * @param in the {@linkplain InputStream} to read plain data from.
	 * @param out the {@linkplain OutputStream} to write encrypted data to.
	 * @return the number of encoded bytes.
	 * @throws IOException if an I/O error occurs.
	 * @throws GeneralSecurityException if an encoding error occurs.
	 */
	public abstract int encrypt(InputStream in, OutputStream out) throws IOException, GeneralSecurityException;

	/**
	 * Encrypt byte data.
	 *
	 * @param plain the plain byte data to encrypt.
	 * @return the encrypted byte data.
	 * @throws GeneralSecurityException if an encoding error occurs.
	 */
	public byte[] encrypt(byte[] plain) throws GeneralSecurityException {
		byte[] encrypted;

		try (InputStream in = new ByteArrayInputStream(plain);
				SafeByteArrayOutputStream out = new SafeByteArrayOutputStream(plain.length);) {
			encrypt(in, out);
			encrypted = out.getBytes();
		} catch (IOException e) {
			throw new GeneralSecurityException(e.getLocalizedMessage(), e);
		}
		return encrypted;
	}

	/**
	 * Decrypt stream data.
	 *
	 * @param in the {@linkplain InputStream} to read encrypted data from.
	 * @param out the {@linkplain OutputStream} to write plain data to.
	 * @return the number of decoded bytes.
	 * @throws IOException if an I/O error occurs.
	 * @throws GeneralSecurityException if an decoding error occurs.
	 */
	public abstract int decrypt(InputStream in, OutputStream out) throws IOException, GeneralSecurityException;

	/**
	 * Decrypt byte data.
	 *
	 * @param encrypted the encrypted byte data to decrypt.
	 * @return the plain byte data.
	 * @throws GeneralSecurityException if an decoding error occurs.
	 */
	public byte[] decrypt(byte[] encrypted) throws GeneralSecurityException {
		byte[] plain;

		try (InputStream in = new ByteArrayInputStream(encrypted);
				SafeByteArrayOutputStream out = new SafeByteArrayOutputStream(encrypted.length);) {
			decrypt(in, out);
			plain = out.getBytes();
		} catch (IOException e) {
			throw new GeneralSecurityException(e.getLocalizedMessage(), e);
		}
		return plain;
	}

	@Override
	public void close() {
		// Nothing to do here
	}

}
