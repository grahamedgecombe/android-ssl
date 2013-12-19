package uk.ac.cam.gpe21.droidssl.mitm.testserver;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class PlainServer {
	public static void main(String[] args) throws IOException {
		System.setProperty("java.net.preferIPv4Stack" ,"true");
		PlainServer server = new PlainServer();
		server.start();
	}

	private final Executor executor = Executors.newCachedThreadPool();
	private final ServerSocket serverSocket;

	public PlainServer() throws IOException {
		this.serverSocket = new ServerSocket(12345);
	}

	public void start() throws IOException {
		while (true) {
			Socket socket = serverSocket.accept();
			executor.execute(new EchoRunnable(socket));
		}
	}
}
