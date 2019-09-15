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
package de.carne.security.test.crypto;

import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import de.carne.boot.logging.Log;
import de.carne.security.crypto.StorableCoder;
import de.carne.security.crypto.StorableCoderId;
import de.carne.security.secret.ByteSecret;
import de.carne.security.util.Randomness;

/**
 * Test all {@linkplain StorableCoder} implementations.
 */
class StorableCoderTest {

	private static final Log LOG = new Log();

	private static byte[] TEST_DATA = new byte[4321];

	static {
		Randomness.get().nextBytes(TEST_DATA);
	}

	@Test
	void testCoders() throws GeneralSecurityException {
		for (StorableCoderId id : StorableCoderId.values()) {
			try (StorableCoder coder = id.newCoder();
					ByteSecret coderSecret = coder.store();
					StorableCoder reloadedCoder = StorableCoder.load(coderSecret);) {
				LOG.info("Testing coder: {0}...", coder);

				testCoder(coder);
				testCoder(reloadedCoder);
			}
		}
	}

	@Test
	void testDefaultCoder() throws GeneralSecurityException {
		try (StorableCoder coder = StorableCoder.defaultCoder().newCoder();
				ByteSecret coderSecret = coder.store();
				StorableCoder reloadedCoder = StorableCoder.load(coderSecret);) {
			LOG.info("Testing default coder: {0}...", coder);

			testCoder(coder);
			testCoder(reloadedCoder);
		}
	}

	private void testCoder(StorableCoder coder) throws GeneralSecurityException {
		byte[] encoded = coder.encrypt(TEST_DATA);
		byte[] decoded = coder.decrypt(encoded);

		Assertions.assertArrayEquals(TEST_DATA, decoded);
	}

}
