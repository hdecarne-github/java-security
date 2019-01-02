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
package de.carne.security.jna.windows;

import com.sun.jna.win32.W32APIOptions;

/**
 * The collection of required library functions.
 */
public final class Native {

	private Native() {
		// prevent instantiation
	}

	/**
	 * Kernel32 library functions.
	 */
	public static final Kernel32Library Kernel32 = com.sun.jna.Native.load("Kernel32", Kernel32Library.class,
			W32APIOptions.UNICODE_OPTIONS);

	/**
	 * Advapi32 library functions.
	 */
	public static final Advapi32Library Advapi32 = com.sun.jna.Native.load("Advapi32", Advapi32Library.class,
			W32APIOptions.UNICODE_OPTIONS);

}
