package uk.ac.cam.gpe21.droidssl.mitm.socket.dest;

import uk.ac.cam.gpe21.droidssl.mitm.socket.SocketUtils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public final class TproxyDestinationFinder extends DestinationFinder {
	@Override
	public ServerSocket openUnboundServerSocket() throws IOException {
		return SocketUtils.openTproxyServerSocket();
	}

	@Override
	public InetSocketAddress getDestination(Socket socket) throws IOException {
		return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
	}
}
