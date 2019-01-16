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

import java.util.Arrays;

import org.eclipse.jdt.annotation.NonNull;

/**
 * {@linkplain Secret} implementation for byte based secrets (e.g. security tokens).
 */
public final class ByteSecret extends Secret<byte @NonNull []> {

	private ByteSecret(byte[] token) {
		super(token);
	}

	/**
	 * Wrap the given token.
	 *
	 * @param token the token to wrap.
	 * @return the {@linkplain ByteSecret} instance holding the given token.
	 */
	public static ByteSecret wrap(byte[] token) {
		return new ByteSecret(token);
	}

	@Override
	protected void disposeSecret(byte[] token) {
		Arrays.fill(token, (byte) 0);
	}

}
