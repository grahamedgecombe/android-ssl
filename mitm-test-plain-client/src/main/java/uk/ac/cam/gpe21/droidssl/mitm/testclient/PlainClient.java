package uk.ac.cam.gpe21.droidssl.mitm.testclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public final class PlainClient {
	public static void main(String[] args) {
		System.setProperty("java.net.preferIPv4Stack" ,"true");
		PlainClient client = new PlainClient();
		try {
			client.start();
		} catch (IOException ex) {
			ex.printStackTrace();
			System.exit(1);
		}
	}

	public void start() throws IOException {
		try (Socket socket = new Socket("127.0.0.1", 12345)) {
			try (InputStream is = socket.getInputStream();
			     OutputStream os = socket.getOutputStream()) {
				os.write(0xFF);

				if (is.read() != 0xFF)
					throw new IOException("Server did not echo back 0xFF byte");
			}
		}
	}
}
