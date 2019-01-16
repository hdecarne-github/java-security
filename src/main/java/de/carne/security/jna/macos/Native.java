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
package de.carne.security.jna.macos;

/**
 * The collection of required framework &amp; library functions.
 */
@SuppressWarnings("squid:S1191")
public final class Native {

	private Native() {
		// prevent instantiation
	}

	/**
	 * CoreFoundation framework functions.
	 */
	public static final CoreFoundationLibrary CoreFoundation = com.sun.jna.Native.load(CoreFoundationLibrary.class);

	/**
	 * Security framework functions.
	 */
	public static final SecurityLibrary Security = com.sun.jna.Native.load(SecurityLibrary.class);

}
