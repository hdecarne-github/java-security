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

import org.eclipse.jdt.annotation.Nullable;

import de.carne.boot.logging.Log;
import de.carne.boot.platform.Platform;

/**
 * {@linkplain SecretStore} implementation using the Windows Crypt API.
 */
final class WindowsSecretStore extends SecretStore {

	private static final Log LOG = new Log();

	private static final boolean ENABLED = Boolean
			.parseBoolean(System.getProperty(WindowsSecretStore.class.getName(), Boolean.TRUE.toString()));

	@Override
	public boolean isAvailable() throws IOException {
		return ENABLED && Platform.IS_WINDOWS;
	}

	@Override
	public boolean hasSecret(String id) throws IOException {
		return false;
	}

	@Override
	public void deleteSecret(String id) throws IOException {
		LOG.info("Deleting secret ''{0}''...", id);

	}

	@Override
	public byte @Nullable [] getSecret(String id) throws IOException {
		LOG.debug("Reading secret ''{0}''...", id);

		return null;
	}

	@Override
	public void setSecret(String id, byte[] secret) throws IOException {
		LOG.info("Setting secret ''{0}''...", id);

	}

}
