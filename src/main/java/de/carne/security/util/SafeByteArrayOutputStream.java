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

import java.io.OutputStream;
import java.util.Arrays;

import org.eclipse.jdt.annotation.Nullable;

import de.carne.boot.check.Check;

/**
 * {@linkplain OutputStream} implementation backed up by a dynamic byte array.
 * <p>
 * In contrast to the standard {@linkplain java.io.ByteArrayOutputStream} implementation this implementation clears the
 * bytes buffer as soon it is no longer used to minimize the a availability of sensitive data in memory to a minimum.
 * </p>
 */
public final class SafeByteArrayOutputStream extends OutputStream {

	private byte[] buf;
	private int pos = 0;

	/**
	 * Constructs a new {@linkplain SafeByteArrayOutputStream} instance.
	 *
	 * @param size the initial buffer size for backing up the instance.
	 */
	public SafeByteArrayOutputStream(int size) {
		Check.isTrue(size >= 0, "Invalid buffer size: {0}", size);

		this.buf = new byte[size];
	}

	/**
	 * Gets the bytes written until now and empties the buffer.
	 *
	 * @return the bytes written until now.
	 */
	public byte[] getBytes() {
		if (this.pos < this.buf.length) {
			setBufferSize(this.pos);
		}

		byte[] bytes = this.buf;

		this.buf = new byte[0];
		this.pos = 0;
		return bytes;
	}

	@Override
	public void write(int b) {
		ensureBufferSize(this.pos + 1);
		this.buf[this.pos] = (byte) (b & 0xff);
		this.pos++;
	}

	@SuppressWarnings("null")
	@Override
	public void write(byte @Nullable [] b) {
		write(b, 0, b.length);
	}

	@Override
	public void write(byte @Nullable [] b, int off, int len) {
		ensureBufferSize(this.pos + len);
		System.arraycopy(b, off, this.buf, this.pos, len);
		this.pos += len;
	}

	private void ensureBufferSize(int size) {
		if (size > this.buf.length) {
			setBufferSize(size);
		}
	}

	private void setBufferSize(int size) {
		byte[] newBuf = new byte[size];

		System.arraycopy(this.buf, 0, newBuf, 0, this.pos);
		Arrays.fill(this.buf, (byte) 0);
		this.buf = newBuf;
	}

	@Override
	public void close() {
		Arrays.fill(this.buf, (byte) 0);
	}

}
