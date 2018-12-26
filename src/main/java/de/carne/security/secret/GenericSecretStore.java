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
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.eclipse.jdt.annotation.Nullable;

import de.carne.boot.Exceptions;
import de.carne.boot.logging.Log;
import de.carne.boot.prefs.FilePreferencesFactory;
import de.carne.boot.prefs.UserFile;

/**
 * Generic file based {@linkplain SecretStore} implementation available on all platforms.
 */
class GenericSecretStore extends SecretStore {

	private static final Log LOG = new Log();

	@Override
	public boolean isAvailable() {
		return true;
	}

	@Override
	public boolean hasSecret(String id) {
		Path secretFile = getSecretFile(id);

		return Files.exists(secretFile, LinkOption.NOFOLLOW_LINKS);
	}

	@Override
	public void deleteSecret(String id) throws IOException {
		Path secretFile = getSecretFile(id);

		LOG.info("Deleting secret file ''{0}''...", secretFile);

		Files.deleteIfExists(secretFile);
	}

	@Override
	public byte @Nullable [] getSecret(String id) throws IOException {
		Path secretFile = getSecretFile(id);

		LOG.debug("Reading secret file ''{0}''...", secretFile);

		byte @Nullable [] secret = null;

		try {
			secret = Files.readAllBytes(secretFile);
		} catch (NoSuchFileException e) {
			Exceptions.ignore(e);
		}
		return secret;
	}

	@Override
	public void setSecret(String id, byte[] secret) throws IOException {
		Path secretFile = getSecretFile(id);

		LOG.info("Writing secret file ''{0}''...", secretFile);

		try (FileChannel file = UserFile.open(secretFile, StandardOpenOption.WRITE,
				StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS)) {
			int written = file.write(ByteBuffer.wrap(secret));

			if (written != secret.length) {
				throw new IOException(
						"Failed to write secret file (" + written + "/" + secret.length + "): " + secretFile);
			}
		}
	}

	private Path getSecretFile(String id) {
		return FilePreferencesFactory.customRootFile(id + ".secret");
	}

}
