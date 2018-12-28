/*
 * Copyright (c) 2018 Holger de Carne and contributors, All Rights Reserved.
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

import com.sun.jna.Library;
import com.sun.jna.Pointer;

/**
 * JNA interface to the required functions of the macOS' CoreFoundation frameworks.
 */
public interface CoreFoundationLibrary extends Library {

	/**
	 * See <a href= "https://developer.apple.com/search/?q=CFStringGetLength">Apple Developer Documentation</a>
	 *
	 * @param theString see Apple Developer Documentation.
	 * @return see Apple Developer Documentation.
	 */
	@SuppressWarnings({ "squid:S00100", "squid:S00107" })
	long/* CFIndex */ CFStringGetLength(Pointer/* CFStringRef */ theString);

	/**
	 * See <a href= "https://developer.apple.com/search/?q=CFStringGetCharacterAtIndex">Apple Developer
	 * Documentation</a>
	 * 
	 * @param theString see Apple Developer Documentation.
	 * @param idx see Apple Developer Documentation.
	 * @return see Apple Developer Documentation.
	 */
	@SuppressWarnings({ "squid:S00100", "squid:S00107" })
	char/* UniChar */ CFStringGetCharacterAtIndex(Pointer/* CFStringRef */ theString, long/* CFIndex */ idx);

	/**
	 * See <a href= "https://developer.apple.com/search/?q=CFRelease">Apple Developer Documentation</a>
	 * 
	 * @param cf see Apple Developer Documentation.
	 */
	@SuppressWarnings({ "squid:S00100", "squid:S00107" })
	void CFRelease(Pointer/* CFTypeRef */ cf);

}
