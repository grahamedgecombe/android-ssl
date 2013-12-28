package uk.ac.cam.gpe21.droidssl.mitm.socket.factory;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public abstract class SocketFactory {
	private final SSLSocketFactory sslSocketFactory;

	public SocketFactory(SSLSocketFactory sslSocketFactory) {
		this.sslSocketFactory = sslSocketFactory;
	}

	public abstract ServerSocket openServerSocket(InetSocketAddress address) throws IOException;
	public abstract Socket openSocket(InetSocketAddress source, InetSocketAddress destination) throws IOException;

	public final SSLSocket openSslSocket(InetSocketAddress source, InetSocketAddress destination) throws IOException {
		return openSslSocket(source, destination, destination.getAddress().getHostAddress());
	}

	public final SSLSocket openSslSocket(InetSocketAddress source, InetSocketAddress destination, String host) throws IOException {
		Socket raw = openSocket(source, destination);
		return (SSLSocket) sslSocketFactory.createSocket(raw, host, destination.getPort(), true);
	}
}
