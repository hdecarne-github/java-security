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

import java.util.Arrays;
import java.util.List;

import org.eclipse.jdt.annotation.Nullable;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;

/**
 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
 * Developer Documentation</a>.
 */
@SuppressWarnings({ "javadoc", "squid:S2160" })
public class CREDENTIAL extends Structure {

	@Override
	protected List<String> getFieldOrder() {
		return Arrays.asList("Flags", "Type", "TargetName", "Comment", "LastWritten", "CredentialBlobSize",
				"CredentialBlob", "Persist", "AttributeCount", "Attributes", "TargetAlias", "UserName");
	}

	public int /* DWORD */ Flags;
	public int /* DWORD */ Type;
	public @Nullable WString /* LPWSTR */ TargetName;
	public @Nullable WString /* LPWSTR */ Comment;
	public long /* FILETIME */ LastWritten;
	public int /* DWORD */ CredentialBlobSize;
	public @Nullable Pointer /* LPBYTE */ CredentialBlob;
	public int /* DWORD */ Persist;
	public int /* DWORD */ AttributeCount;
	public @Nullable Pointer /* PCREDENTIAL_ATTRIBUTE */ Attributes;
	public @Nullable WString /* LPWSTR */ TargetAlias;
	public @Nullable WString /* LPWSTR */ UserName;

	/**
	 * Construct a new uninitialized {@linkplain CREDENTIAL} instance.
	 */
	public CREDENTIAL() {
		// Nothing to do here
	}

	/**
	 * Construct a new initialized {@linkplain CREDENTIAL} instance.
	 * 
	 * @param pointer pointer to use for initialization.
	 */
	public CREDENTIAL(Pointer pointer) {
		super(pointer);
		read();
	}

}
