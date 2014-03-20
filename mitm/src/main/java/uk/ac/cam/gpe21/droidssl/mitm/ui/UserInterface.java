package uk.ac.cam.gpe21.droidssl.mitm.ui;

import java.io.IOException;

public abstract class UserInterface {
	public abstract void init(String title, String caPrefix, String hostnameFinder);
	public abstract void onOpen(Session session);
	public abstract void onData(Session session, boolean receive, byte[] buf, int len);
	public abstract void onClose(Session session);
	public abstract void onFailure(Session session, IOException reason);
}
