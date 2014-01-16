package uk.ac.cam.gpe21.droidssl.mitm;

import uk.ac.cam.gpe21.droidssl.mitm.ui.Session;
import uk.ac.cam.gpe21.droidssl.mitm.ui.UserInterface;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IoCopyRunnable implements Runnable {
	private final Session session;
	private final boolean receive;
	private final InputStream in;
	private final OutputStream out;
	private final UserInterface ui;

	public IoCopyRunnable(Session session, boolean receive, InputStream in, OutputStream out, UserInterface ui) {
		this.session = session;
		this.receive = receive;
		this.in = in;
		this.out = out;
		this.ui = ui;
	}

	@Override
	public void run() {
		try {
			byte[] buf = new byte[4096];
			int n;
			while ((n = in.read(buf, 0, buf.length)) != -1) {
				ui.onData(session, receive, buf, n);
				out.write(buf, 0, n);
			}

			session.setState(Session.State.CLOSED); // TODO sync
			ui.onClose(session);
		} catch (IOException ex) {
			session.setState(Session.State.FAILED); // TODO sync
			session.setFailureReason(ex); // TODO sync
			ui.onFailure(session, ex);
		}
	}
}
