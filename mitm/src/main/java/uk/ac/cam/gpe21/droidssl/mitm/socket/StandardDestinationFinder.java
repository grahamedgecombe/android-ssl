package uk.ac.cam.gpe21.droidssl.mitm.socket;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public final class StandardDestinationFinder extends DestinationFinder {
	@Override
	public InetSocketAddress getDestination(Socket socket) throws IOException {
		return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
	}
}
