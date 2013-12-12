package uk.ac.cam.gpe21.droidssl.mitm.testclient;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public final class PermissiveHostnameVerifier implements HostnameVerifier {
	@Override
	public boolean verify(String hostname, SSLSession session) {
		return true;
	}
}
