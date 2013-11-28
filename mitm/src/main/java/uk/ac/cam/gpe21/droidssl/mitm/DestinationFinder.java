package uk.ac.cam.gpe21.droidssl.mitm;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public abstract class DestinationFinder {
	public abstract InetSocketAddress getDestination(Socket socket) throws IOException;
}
