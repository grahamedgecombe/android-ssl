package uk.ac.cam.gpe21.droidssl.mitm.testclient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public final class TestClient {
	public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, IOException {
		TestClient client = new TestClient(new InetSocketAddress("localhost", 12345));
		client.start();
	}

	private final InetSocketAddress address;
	private final SSLSocketFactory factory;

	public TestClient(InetSocketAddress address) throws NoSuchAlgorithmException, KeyManagementException {
		this.address = address;

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, null, null);
		this.factory = context.getSocketFactory();
	}

	public void start() throws IOException {
		SSLSocket socket = (SSLSocket) factory.createSocket(address.getAddress(), address.getPort());
		socket.startHandshake();
	}
}
