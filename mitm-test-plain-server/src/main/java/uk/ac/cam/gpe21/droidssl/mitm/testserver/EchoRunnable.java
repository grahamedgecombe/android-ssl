package uk.ac.cam.gpe21.droidssl.mitm.testserver;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public final class EchoRunnable implements Runnable {
	private final Socket socket;

	public EchoRunnable(Socket socket) {
		this.socket = socket;
	}

	@Override
	public void run() {
		try (InputStream is = socket.getInputStream();
			 OutputStream os = socket.getOutputStream()) {
			byte[] buf = new byte[4096];
			int len;
			while ((len = is.read(buf, 0, buf.length)) != -1) {
				os.write(buf, 0, len);
			}
		} catch (IOException ex) {
			/* ignore (thread will terminate automatically) */
		}
	}
}
