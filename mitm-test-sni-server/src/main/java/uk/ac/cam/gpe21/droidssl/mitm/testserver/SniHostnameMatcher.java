package uk.ac.cam.gpe21.droidssl.mitm.testserver;

import javax.net.ssl.*;

public final class SniHostnameMatcher extends SNIMatcher {
	private String hostname;

	protected SniHostnameMatcher() {
		super(StandardConstants.SNI_HOST_NAME);
	}

	@Override
	public boolean matches(SNIServerName name) {
		SNIHostName hostname = (SNIHostName) name;
		String str = hostname.getAsciiName();
		boolean accept = str.equals("default.example.com") || str.equals("test1.example.com") || str.equals("test2.example.com");
		if (accept) {
			this.hostname = str;
		}
		return accept;
	}

	public boolean isSniEnabled() {
		return hostname != null;
	}

	public String getSniHostname() {
		return hostname;
	}
}
