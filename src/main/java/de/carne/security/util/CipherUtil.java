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
package de.carne.security.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;

/**
 * Utility class providing {@linkplain Cipher} related functions.
 */
public final class CipherUtil {

	private static final int STREAM_BUFFER_SIZE = 512;

	private CipherUtil() {
		// prevent instantiation
	}

	public static int stream(Cipher cipher, InputStream in, OutputStream out)
			throws IOException, GeneralSecurityException {
		int read = 0;
		byte[] inBuffer = new byte[STREAM_BUFFER_SIZE];
		byte[] outBuffer = null;

		try {
			int read0 = 0;

			while (read0 >= 0) {
				read0 = in.read(inBuffer);
				if (read0 > 0) {
					read += read0;
					outBuffer = cipher.update(inBuffer, 0, read0);
				} else if (read0 < 0) {
					outBuffer = cipher.doFinal();
				}
				if (outBuffer != null) {
					out.write(outBuffer);
				}
				Arrays.fill(outBuffer, (byte) 0);
				outBuffer = null;
			}
		} finally {
			Arrays.fill(inBuffer, (byte) 0);
			if (outBuffer != null) {
				Arrays.fill(outBuffer, (byte) 0);
			}
		}
		return read;
	}

}
