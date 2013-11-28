package uk.ac.cam.gpe21.droidssl.mitm;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public final class FixedDestinationFinder extends DestinationFinder {
	private final InetSocketAddress address;

	public FixedDestinationFinder(InetSocketAddress address) {
		this.address = address;
	}

	@Override
	public InetSocketAddress getDestination(Socket socket) throws IOException {
		return address;
	}
}
