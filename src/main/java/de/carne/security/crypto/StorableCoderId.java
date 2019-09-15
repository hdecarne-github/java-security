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

/**
 * Supported {@linkplain StorableCoder} types.
 */
public enum StorableCoderId {

	/**
	 * AES128 coder.
	 */
	AES128(new AES128CoderFactory()),

	/**
	 * AES256 coder.
	 */
	AES256(new AES256CoderFactory());

	private final StorableCoderFactory factory;

	private StorableCoderId(StorableCoderFactory factory) {
		this.factory = factory;
	}

	/**
	 * Creates a new {@linkplain StorableCoder} instance for the represented coder type.
	 * 
	 * @return the new {@linkplain StorableCoder} instance.
	 * @throws GeneralSecurityException if a security error occurs.
	 */
	public StorableCoder newCoder() throws GeneralSecurityException {
		return this.factory.newCoder();
	}

	/**
	 * Loads a previously stored {@linkplain StorableCoder} instance for the represented coder type.
	 * 
	 * @param secret the {@linkplain ByteSecret} to load the {@linkplain StorableCoder} instance from.
	 * @return the loaded {@linkplain StorableCoder} instance.
	 * @throws GeneralSecurityException if a security error occurs.
	 */
	public StorableCoder loadCoder(ByteSecret secret) throws GeneralSecurityException {
		return secret.apply(plain -> this.factory.loadCoder(plain, 0, plain.length));
	}

}
