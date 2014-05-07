/*
 * Copyright 2013-2014 Graham Edgecombe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.ac.cam.gpe21.droidssl.mitm.util;

import java.net.InetSocketAddress;

public final class SocketAddressParser {
	public static InetSocketAddress parse(String str) {
		String address, port;

		if (str.startsWith("[")) {
			int addressEnd = str.indexOf(']');
			if (addressEnd == -1)
				throw new IllegalArgumentException();

			if ((addressEnd + 2) > str.length())
				throw new IllegalArgumentException();

			address = str.substring(1, addressEnd);
			if (str.charAt(addressEnd + 1) != ':')
				throw new IllegalArgumentException();

			port = str.substring(addressEnd + 2);
		} else {
			String[] parts = str.split(":");
			if (parts.length != 2)
				throw new IllegalArgumentException();

			address = parts[0];
			port = parts[1];
		}

		return new InetSocketAddress(address, Integer.parseInt(port));
	}

	private SocketAddressParser() {
		/* to prevent instantiation */
	}
}
