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
package de.carne.security;

/**
 * This error indicates an fatal error situation from a security point of view.
 */
public class SecurityError extends Error {

	// Serialization support
	private static final long serialVersionUID = 3524702606980806066L;

	/**
	 * Constructs a new {@linkplain SecurityError}.
	 *
	 * @param cause the causing exception.
	 */
	public SecurityError(Throwable cause) {
		super(cause.getLocalizedMessage(), cause);
	}

}
