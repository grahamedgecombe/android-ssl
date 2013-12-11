package uk.ac.cam.gpe21.droidssl.mitm.testserver;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class TestServer {
	public static void main(String[] args) throws IOException, KeyManagementException, NoSuchAlgorithmException {
		TestServer server = new TestServer();
		server.start();
	}

	private final Executor executor = Executors.newCachedThreadPool();
	private final SSLServerSocket serverSocket;

	public TestServer() throws NoSuchAlgorithmException, KeyManagementException, IOException {
		SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, null, null);
		this.serverSocket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(12345);
	}

	public void start() throws IOException {
		while (true) {
			SSLSocket socket = (SSLSocket) serverSocket.accept();
			executor.execute(new EchoRunnable(socket));
		}
	}
}
