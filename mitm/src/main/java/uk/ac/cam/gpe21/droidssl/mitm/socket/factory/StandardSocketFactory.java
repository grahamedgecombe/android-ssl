package uk.ac.cam.gpe21.droidssl.mitm.socket.factory;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public final class StandardSocketFactory extends SocketFactory {
	public StandardSocketFactory(SSLSocketFactory sslSocketFactory) {
		super(sslSocketFactory);
	}

	@Override
	public ServerSocket openServerSocket(InetSocketAddress address) throws IOException {
		ServerSocket socket = new ServerSocket();
		socket.bind(address);
		return socket;
	}

	@Override
	public Socket openSocket(InetSocketAddress source, InetSocketAddress destination) throws IOException {
		Socket socket = new Socket();
		socket.connect(destination);
		return socket;
	}
}
