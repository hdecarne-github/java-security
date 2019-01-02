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

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

/**
 * JNA interface to the required functions of the Win32' Advapi32 library.
 */
@SuppressWarnings("squid:S1214")
public interface Advapi32Library extends StdCallLibrary {

	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_TYPE_GENERIC = 1;
	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_TYPE_DOMAIN_PASSWORD = 2;
	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_TYPE_DOMAIN_CERTIFICATE = 3;
	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 4;
	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_TYPE_GENERIC_CERTIFICATE = 5;
	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_TYPE_DOMAIN_EXTENDED = 6;

	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/nf-wincred-credwritew">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_PRESERVE_CREDENTIAL_BLOB = 1;

	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_FLAGS_PROMPT_NOW = 2;
	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_FLAGS_USERNAME_TARGET = 4;

	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_PERSIST_SESSION = 1;
	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_PERSIST_LOCAL_MACHINE = 2;
	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/ns-wincred-_credentialw">Microsoft
	 * Developer Documentation</a>
	 */
	int CRED_PERSIST_ENTERPRISE = 3;

	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/nf-wincred-credreadw">Microsoft
	 * Developer Documentation</a>
	 *
	 * @param TargetName see Microsoft Developer Documentation.
	 * @param Type see Microsoft Developer Documentation.
	 * @param Flags see Microsoft Developer Documentation.
	 * @param Credential see Microsoft Developer Documentation.
	 * @return see Microsoft Developer Documentation.
	 */
	@SuppressWarnings({ "squid:S00100", "squid:S00107", "squid:S00117" })
	boolean/* BOOL */ CredRead(String/* LPCSTR */ TargetName, int/* DWORD */ Type, int/* DWORD */ Flags,
			PointerByReference/* PCREDENTIAL * */ Credential);

	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/nf-wincred-credwritew">Microsoft
	 * Developer Documentation</a>
	 *
	 * @param Credential see Microsoft Developer Documentation.
	 * @param Flags see Microsoft Developer Documentation.
	 * @return see Microsoft Developer Documentation.
	 */
	@SuppressWarnings({ "squid:S00100", "squid:S00107", "squid:S00117" })
	boolean/* BOOL */ CredWrite(CREDENTIAL/* PCREDENTIAL */ Credential, int/* DWORD */ Flags);

	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/nf-wincred-creddeletew">Microsoft
	 * Developer Documentation</a>
	 *
	 * @param TargetName see Microsoft Developer Documentation.
	 * @param Type see Microsoft Developer Documentation.
	 * @param Flags see Microsoft Developer Documentation.
	 * @return see Microsoft Developer Documentation.
	 */
	@SuppressWarnings({ "squid:S00100", "squid:S00107", "squid:S00117" })
	boolean/* BOOL */ CredDelete(String/* LPCSTR */ TargetName, int/* DWORD */ Type, int /* DWORD */ Flags);

	/**
	 * See <a href="https://docs.microsoft.com/en-us/windows/desktop/api/wincred/nf-wincred-credfree">Microsoft
	 * Developer Documentation</a>
	 *
	 * @param Buffer see Microsoft Developer Documentation.
	 */
	@SuppressWarnings({ "squid:S00100", "squid:S00107", "squid:S00117" })
	void CredFree(Pointer /* PVOID */ Buffer);

}
