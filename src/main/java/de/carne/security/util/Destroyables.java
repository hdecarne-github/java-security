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
package de.carne.security.util;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import de.carne.boot.logging.Log;
import de.carne.security.SecurityError;

/**
 * Utility class providing {@linkplain Destroyable} related functions.
 */
public final class Destroyables {

	private static final Log LOG = new Log();

	private Destroyables() {
		// prevent instantiation
	}

	/**
	 * Invokes {@linkplain Destroyable#destroy()} on the given {@linkplain Destroyable} and maps any relevant
	 * {@linkplain DestroyFailedException} to a {@linkplain SecurityError}.
	 *
	 * @param destroyable the {@linkplain Destroyable} instance to destroy.
	 */
	public static void safeDestroy(Destroyable destroyable) {
		if (!destroyable.isDestroyed()) {
			try {
				destroyable.destroy();
			} catch (DestroyFailedException e) {
				// Ignore exceptions thrown by default implementation
				StackTraceElement[] stes = e.getStackTrace();

				if (stes.length > 0 && !Destroyable.class.getName().equals(stes[0].getClassName())) {
					LOG.error(e, "Failed to destroy security object (type: {0})", destroyable.getClass().getName());
					throw new SecurityError(e);
				}
			}
		}
	}

}
