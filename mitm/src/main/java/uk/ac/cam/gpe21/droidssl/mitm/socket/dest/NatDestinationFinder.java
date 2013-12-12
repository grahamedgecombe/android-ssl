package uk.ac.cam.gpe21.droidssl.mitm.socket.dest;

import uk.ac.cam.gpe21.droidssl.mitm.socket.SocketUtils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public final class NatDestinationFinder extends DestinationFinder {
	@Override
	public InetSocketAddress getDestination(Socket socket) throws IOException {
		return SocketUtils.getOriginalDestination(socket);
	}
}
