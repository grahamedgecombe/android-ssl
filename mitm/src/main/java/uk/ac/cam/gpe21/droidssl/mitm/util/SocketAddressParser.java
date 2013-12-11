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
