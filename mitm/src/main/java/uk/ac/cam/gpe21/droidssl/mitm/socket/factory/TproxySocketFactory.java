package uk.ac.cam.gpe21.droidssl.mitm.socket.factory;

import uk.ac.cam.gpe21.droidssl.mitm.socket.SocketUtils;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public final class TproxySocketFactory extends SocketFactory {
	public TproxySocketFactory(SSLSocketFactory sslSocketFactory) {
		super(sslSocketFactory);
	}

	@Override
	public ServerSocket openServerSocket(InetSocketAddress address) throws IOException {
		ServerSocket socket = SocketUtils.openTproxyServerSocket();
		socket.bind(address);
		return socket;
	}

	@Override
	public Socket openSocket(InetSocketAddress source, InetSocketAddress destination) throws IOException {
		// TODO: this won't work for SNI yet, as we open a second socket while
		// the first socket is still open and they cannot share the same source
		// address.
		Socket socket = SocketUtils.openTproxySocket();
		socket.bind(source);
		socket.connect(destination);
		return socket;
	}
}
