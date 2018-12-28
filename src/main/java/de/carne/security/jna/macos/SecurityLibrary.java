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

import org.eclipse.jdt.annotation.Nullable;

import com.sun.jna.Library;
import com.sun.jna.Pointer;

/**
 * JNA interface to the required functions of the macOS' Security frameworks.
 */
public interface SecurityLibrary extends Library {

	/**
	 * See <a href= "https://developer.apple.com/search/?q=SecKeychainAddGenericPassword">Apple Developer
	 * Documentation</a>
	 */
	@SuppressWarnings({ "javadoc", "squid:S00100", "squid:S00107" })
	int/* OSStatus */ SecKeychainAddGenericPassword(@Nullable Pointer/* SecKeychainRef */ keychain,
			int/* UInt32 */ serviceNameLength, byte[]/* const char * */ serviceName, int/* UInt32 */ accountNameLength,
			byte[]/* const char * */ accountName, int/* UInt32 */ passwordLength, byte[]/* const void * */ passwordData,
			@Nullable Pointer/* ecKeychainItemRef _Nullable * */ itemRef);

	/**
	 * See <a href= "https://developer.apple.com/search/?q=SecKeychainItemModifyContent">Apple Developer
	 * Documentation</a>
	 */
	@SuppressWarnings({ "javadoc", "squid:S00100", "squid:S00107" })
	int/* OSStatus */ SecKeychainItemModifyContent(Pointer/* SecKeychainItemRef */ itemRef,
			@Nullable Pointer/* const SecKeychainAttributeList * */ attrList, int/* UInt32 */ length,
			byte[]/* const void * */ data);

	/**
	 * See <a href= "https://developer.apple.com/search/?q=SecKeychainFindGenericPassword">Apple Developer
	 * Documentation</a>
	 */
	@SuppressWarnings({ "javadoc", "squid:S00100", "squid:S00107" })
	int/* OSStatus */ SecKeychainFindGenericPassword(@Nullable Pointer/* CFTypeRef */ keychainOrArray,
			int/* UInt32 */ serviceNameLength, byte[]/* const char * */ serviceName, int/* UInt32 */ accountNameLength,
			byte[]/* const char * */ accountName, int @Nullable []/* UInt32 * */ passwordLength,
			Pointer @Nullable []/* void * _Nullable * */ passwordData,
			@Nullable Pointer/* SecKeychainItemRef _Nullable * */ @Nullable [] itemRef);

	/**
	 * See <a href= "https://developer.apple.com/search/?q=SecKeychainItemDelete">Apple Developer Documentation</a>
	 */
	@SuppressWarnings({ "javadoc", "squid:S00100", "squid:S00107" })
	int SecKeychainItemDelete(Pointer/* SecKeychainItemRef */ itemRef);

	/**
	 * See <a href= "https://developer.apple.com/search/?q=SecKeychainItemDelete">Apple Developer Documentation</a>
	 */
	@SuppressWarnings({ "javadoc", "squid:S00100", "squid:S00107" })
	int/* OSStatus */ SecKeychainItemFreeContent(@Nullable Pointer/* SecKeychainAttributeList * */ attrList,
			@Nullable Pointer /* void * */ data);

	/**
	 * See <a href= "https://developer.apple.com/search/?q=SecCopyErrorMessageString">Apple Developer Documentation</a>
	 */
	@SuppressWarnings({ "javadoc", "squid:S00100", "squid:S00107" })
	@Nullable
	Pointer/* CFStringRef */ SecCopyErrorMessageString(int/* OSStatus */ status,
			@Nullable Pointer/* void * */ reserved);

}
