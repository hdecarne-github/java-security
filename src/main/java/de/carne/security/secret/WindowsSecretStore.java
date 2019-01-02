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

import java.io.IOException;
import java.util.Objects;

import org.eclipse.jdt.annotation.Nullable;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.ptr.PointerByReference;

import de.carne.boot.logging.Log;
import de.carne.boot.platform.Platform;
import de.carne.security.jna.windows.Advapi32Library;
import de.carne.security.jna.windows.CREDENTIAL;
import de.carne.security.jna.windows.Native;

/**
 * {@linkplain SecretStore} implementation using the Windows Crypt API.
 */
final class WindowsSecretStore extends SecretStore {

	private static final Log LOG = new Log();

	private static final boolean ENABLED = Boolean
			.parseBoolean(System.getProperty(WindowsSecretStore.class.getName(), Boolean.TRUE.toString()));

	private static final String TARGET_NAME_PREFIX = "Java_SecureStorage:";

	@Override
	public boolean isAvailable() throws IOException {
		return ENABLED && Platform.IS_WINDOWS;
	}

	@Override
	public boolean hasSecret(String id) throws IOException {
		PointerByReference credentialReference = new PointerByReference();
		boolean found = Native.Advapi32.CredRead(getTargetName(id), Advapi32Library.CRED_TYPE_GENERIC, 0,
				credentialReference);

		if (found) {
			Pointer pCredential = Objects.requireNonNull(credentialReference.getValue());

			Native.Advapi32.CredFree(pCredential);
		}
		return found;
	}

	@Override
	public void deleteSecret(String id) throws IOException {
		LOG.info("Deleting secret ''{0}''...", id);

		boolean success = Native.Advapi32.CredDelete(getTargetName(id), Advapi32Library.CRED_TYPE_GENERIC, 0);

		if (!success) {
			throw statusException();
		}
	}

	@Override
	public byte @Nullable [] getSecret(String id) throws IOException {
		LOG.debug("Reading secret ''{0}''...", id);

		PointerByReference credentialReference = new PointerByReference();
		boolean found = Native.Advapi32.CredRead(getTargetName(id), Advapi32Library.CRED_TYPE_GENERIC, 0,
				credentialReference);
		byte[] secret = null;

		if (found) {
			Pointer pCredential = Objects.requireNonNull(credentialReference.getValue());
			CREDENTIAL credential = new CREDENTIAL(pCredential);
			Pointer credentialBlob = Objects.requireNonNull(credential.CredentialBlob);

			secret = credentialBlob.getByteArray(0, credential.CredentialBlobSize);
			credentialBlob.clear(credential.CredentialBlobSize);
			Native.Advapi32.CredFree(pCredential);
		}
		return secret;
	}

	@Override
	public void setSecret(String id, byte[] secret) throws IOException {
		LOG.info("Setting secret ''{0}''...", id);

		CREDENTIAL credential = new CREDENTIAL();

		credential.Flags = 0;
		credential.Type = Advapi32Library.CRED_TYPE_GENERIC;
		credential.TargetName = new WString(getTargetName(id));
		credential.Comment = null;
		credential.CredentialBlobSize = secret.length;

		Memory secretMemory = new Memory(secret.length);

		secretMemory.write(0, secret, 0, secret.length);
		credential.CredentialBlob = secretMemory;
		credential.Persist = Advapi32Library.CRED_PERSIST_LOCAL_MACHINE;
		credential.AttributeCount = 0;
		credential.Attributes = null;
		credential.TargetAlias = null;
		credential.UserName = new WString(getUserName());

		boolean success = Native.Advapi32.CredWrite(credential, 0);

		secretMemory.clear();
		if (!success) {
			throw statusException();
		}
	}

	private String getTargetName(String id) {
		return TARGET_NAME_PREFIX + id;
	}

	private String getUserName() {
		return Objects.requireNonNull(System.getProperty("user.name"));
	}

	private IOException statusException() {
		StringBuilder message = new StringBuilder();

		message.append("Credential function failure");

		int status = Native.Kernel32.GetLastError();

		if (status != 0) {
			message.append(" (").append(status).append(")");
		}
		return new IOException(message.toString());
	}

}
