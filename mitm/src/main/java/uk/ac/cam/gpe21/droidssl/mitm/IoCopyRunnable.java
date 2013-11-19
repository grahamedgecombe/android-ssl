package uk.ac.cam.gpe21.droidssl.mitm;

import uk.ac.cam.gpe21.droidssl.mitm.util.HexFormat;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IoCopyRunnable implements Runnable {
	private final InputStream in;
	private final OutputStream out;

	public IoCopyRunnable(InputStream in, OutputStream out) {
		this.in = in;
		this.out = out;
	}

	@Override
	public void run() {
		try {
			byte[] buf = new byte[4096];
			int n;
			while ((n = in.read(buf, 0, buf.length)) != -1) {
				System.out.println(HexFormat.format(buf, n));
				out.write(buf, 0, n);
			}
		} catch (IOException ex) {
			// TODO deal with properly (print warning, close socket?)
		}
	}
}
