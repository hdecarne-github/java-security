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
 * {@linkplain Secret} implementation for character based secrets (e.g. passwords).
 */
public final class CharSecret extends Secret<char @NonNull []> {

	private CharSecret(char[] password) {
		super(password);
	}

	/**
	 * Wrap the given password.
	 *
	 * @param password the password to wrap.
	 * @return the {@linkplain CharSecret} instance holding the given password.
	 */
	public static CharSecret wrap(char[] password) {
		return new CharSecret(password);
	}

	@Override
	protected void disposeSecret(char[] password) {
		Arrays.fill(password, '\0');
	}

}
