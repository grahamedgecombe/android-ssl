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
			boolean receivedData = false;
			byte[] buf = new byte[4096];
			int n;
			while ((n = in.read(buf, 0, buf.length)) != -1) {
				if (n > 0)
					receivedData = true;

				ui.onData(session, receive, buf, n);
				out.write(buf, 0, n);
			}

			/*
			 * If the device (our receiving end) closed the connection and did
			 * not send any data, we deem it to have 'maybe' failed (typically
			 * on Android when an application deems the cert invalid it
			 * immediately closes the connection - of course, a connection
			 * could have no data sent over it, but this would not be a very
			 * interesting connection anyway!)
			 */
			session.setState((receive && !receivedData) ? Session.State.MAYBE_FAILED : Session.State.CLOSED);
			ui.onClose(session);
		} catch (IOException ex) {
			session.setState(Session.State.FAILED);
			session.setFailureReason(ex);
			ui.onFailure(session, ex);
		}
	}
}
