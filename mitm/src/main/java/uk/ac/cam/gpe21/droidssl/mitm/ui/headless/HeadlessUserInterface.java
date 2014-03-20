package uk.ac.cam.gpe21.droidssl.mitm.ui.headless;

import uk.ac.cam.gpe21.droidssl.mitm.ui.Session;
import uk.ac.cam.gpe21.droidssl.mitm.ui.UserInterface;
import uk.ac.cam.gpe21.droidssl.mitm.util.HexFormat;

import java.io.IOException;

public final class HeadlessUserInterface extends UserInterface {
	@Override
	public void init(String title, String caPrefix, String hostnameFinder) {
		/* empty */
	}

	@Override
	public void onOpen(Session session) {
		/* empty */
	}

	@Override
	public void onData(Session session, boolean receive, byte[] buf, int len) {
		System.out.println(HexFormat.format(buf, len));
	}

	@Override
	public void onClose(Session session) {
		/* empty */
	}

	@Override
	public void onFailure(Session session, IOException reason) {
		/* empty */
	}
}
