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

import java.security.GeneralSecurityException;

/**
 * Descendants of this class are used to wrap sensitive data and make sure it is properly overwritten in memory when it
 * is no longer used.
 *
 * @param <T> the actual secret type.
 */
public abstract class Secret<T> implements AutoCloseable {

	private final T data;

	protected Secret(T data) {
		this.data = data;
	}

	public void accept(SecretConsumer<T> consumer) throws GeneralSecurityException {
		consumer.accept(this.data);
	}

	public <E> E apply(SecretFunction<T, E> function) throws GeneralSecurityException {
		return function.apply(this.data);
	}

	@Override
	public final void close() {
		disposeSecret(this.data);
	}

	/**
	 * Dispose the secret data (e.g. by overwriting it).
	 *
	 * @param secretData the secret data to dispose.
	 */
	protected abstract void disposeSecret(T secretData);

}
