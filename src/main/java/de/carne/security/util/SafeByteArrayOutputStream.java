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

/**
 *
 */
public final class SafeByteArrayOutputStream extends OutputStream {

	private byte[] buf;
	private int pos = 0;

	public SafeByteArrayOutputStream(int size) {
		this.buf = new byte[size];
	}

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
