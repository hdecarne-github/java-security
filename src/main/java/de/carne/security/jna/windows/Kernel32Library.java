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

import com.sun.jna.win32.StdCallLibrary;

/**
 * JNA interface to the required functions of the Win32' Kernel32 library.
 */
public interface Kernel32Library extends StdCallLibrary {

	/**
	 * See <a href="https://msdn.microsoft.com/en-us/d852e148-985c-416f-a5a7-27b6914b45d4">Microsoft Developer
	 * Documentation</a>
	 *
	 * @return see Microsoft Developer Documentation.
	 */
	@SuppressWarnings({ "squid:S00100", "squid:S00107" })
	int/* DWORD */ GetLastError();

}
