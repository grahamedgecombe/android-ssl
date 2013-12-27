package uk.ac.cam.gpe21.droidssl.mitm.socket.dest;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public abstract class DestinationFinder {
	public ServerSocket openUnboundServerSocket() throws IOException {
		return new ServerSocket();
	}

	public abstract InetSocketAddress getDestination(Socket socket) throws IOException;
}
