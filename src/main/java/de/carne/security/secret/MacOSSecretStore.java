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
package de.carne.security.secret;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.eclipse.jdt.annotation.Nullable;

import com.sun.jna.Pointer;

import de.carne.boot.platform.Platform;
import de.carne.security.jna.macos.Native;

/**
 *
 */
final class MacOSSecretStore extends SecretStore {

	private static final boolean ENABLED = Boolean
			.parseBoolean(System.getProperty(MacOSSecretStore.class.getName(), Boolean.TRUE.toString()));

	@Override
	public boolean isAvailable() throws IOException {
		return ENABLED && Platform.IS_MACOS;
	}

	@SuppressWarnings("null")
	private static final String ACCOUNT_NAME = System.getProperty("user.name", "anonymous");

	private static final int STATUS_SUCCESS = 0;
	private static final int STATUS_SEC_ITEM_NOT_FOUND = -25300;

	@Override
	public boolean hasSecret(String id) throws IOException {
		byte[] serviceNameBytes = id.getBytes(StandardCharsets.UTF_8);
		byte[] accountNameBytes = ACCOUNT_NAME.getBytes(StandardCharsets.UTF_8);
		int findStatus = Native.Security.SecKeychainFindGenericPassword(null, serviceNameBytes.length, serviceNameBytes,
				accountNameBytes.length, accountNameBytes, null, null, null);

		if (findStatus != STATUS_SUCCESS && findStatus != STATUS_SEC_ITEM_NOT_FOUND) {
			throw statusException(findStatus);
		}
		return findStatus == STATUS_SUCCESS;
	}

	@Override
	public void deleteSecret(String id) throws IOException {
		byte[] serviceNameBytes = id.getBytes(StandardCharsets.UTF_8);
		byte[] accountNameBytes = ACCOUNT_NAME.getBytes(StandardCharsets.UTF_8);
		@Nullable Pointer[] itemRef = new @Nullable Pointer[1];
		int findStatus = Native.Security.SecKeychainFindGenericPassword(null, serviceNameBytes.length, serviceNameBytes,
				accountNameBytes.length, accountNameBytes, null, null, itemRef);

		if (findStatus != STATUS_SUCCESS && findStatus != STATUS_SEC_ITEM_NOT_FOUND) {
			throw statusException(findStatus);
		}
		if (findStatus == STATUS_SUCCESS) {
			Pointer foundItemRef = Objects.requireNonNull(itemRef[0]);
			int deleteStatus = Native.Security.SecKeychainItemDelete(foundItemRef);

			Native.CoreFoundation.CFRelease(foundItemRef);
			verifyStatusSuccess(deleteStatus);
		}
	}

	@Override
	public byte @Nullable [] getSecret(String id) throws IOException {
		byte[] serviceNameBytes = id.getBytes(StandardCharsets.UTF_8);
		byte[] accountNameBytes = ACCOUNT_NAME.getBytes(StandardCharsets.UTF_8);
		int[] passwordLength = new int[1];
		@Nullable Pointer[] passwordData = new @Nullable Pointer[1];
		int findStatus = Native.Security.SecKeychainFindGenericPassword(null, serviceNameBytes.length, serviceNameBytes,
				accountNameBytes.length, accountNameBytes, passwordLength, passwordData, null);

		if (findStatus != STATUS_SUCCESS && findStatus != STATUS_SEC_ITEM_NOT_FOUND) {
			throw statusException(findStatus);
		}

		byte[] secret = null;

		if (findStatus == STATUS_SUCCESS) {
			Pointer foundPasswordData = Objects.requireNonNull(passwordData[0]);

			secret = foundPasswordData.getByteArray(0, passwordLength[0]);
			verifyStatusSuccess(Native.Security.SecKeychainItemFreeContent(null, foundPasswordData));
		}
		return secret;
	}

	@Override
	public void setSecret(String id, byte[] secret) throws IOException {
		byte[] serviceNameBytes = id.getBytes(StandardCharsets.UTF_8);
		byte[] accountNameBytes = ACCOUNT_NAME.getBytes(StandardCharsets.UTF_8);
		@Nullable Pointer[] itemRef = new @Nullable Pointer[1];
		int findStatus = Native.Security.SecKeychainFindGenericPassword(null, serviceNameBytes.length, serviceNameBytes,
				accountNameBytes.length, accountNameBytes, null, null, itemRef);

		if (findStatus != STATUS_SUCCESS && findStatus != STATUS_SEC_ITEM_NOT_FOUND) {
			throw statusException(findStatus);
		}
		if (findStatus == STATUS_SUCCESS) {
			Pointer foundItemRef = Objects.requireNonNull(itemRef[0]);
			int modifyStatus = Native.Security.SecKeychainItemModifyContent(foundItemRef, null, secret.length, secret);

			Native.CoreFoundation.CFRelease(foundItemRef);
			verifyStatusSuccess(modifyStatus);
		} else {
			verifyStatusSuccess(Native.Security.SecKeychainAddGenericPassword(null, serviceNameBytes.length,
					serviceNameBytes, accountNameBytes.length, accountNameBytes, secret.length, secret, null));
		}
	}

	private IOException statusException(int status) {
		StringBuilder message = new StringBuilder();

		message.append("Keychain function failure (").append(status);

		Pointer statusMessage = Native.Security.SecCopyErrorMessageString(status, null);

		if (statusMessage != null) {
			message.append(": ");

			int statusMessageLength = (int) Math.min(Native.CoreFoundation.CFStringGetLength(statusMessage),
					Short.MAX_VALUE);

			message.ensureCapacity(message.length() + statusMessageLength);
			for (int statusMessageCharIndex = 0; statusMessageCharIndex < statusMessageLength; statusMessageCharIndex++) {
				message.append(
						Native.CoreFoundation.CFStringGetCharacterAtIndex(statusMessage, statusMessageCharIndex));
			}
			Native.CoreFoundation.CFRelease(statusMessage);
		}
		message.append(")");
		return new IOException(message.toString());
	}

	private void verifyStatusSuccess(int status) throws IOException {
		if (status != STATUS_SUCCESS) {
			throw statusException(status);
		}
	}

}
