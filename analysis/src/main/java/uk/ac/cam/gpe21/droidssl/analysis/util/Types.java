package uk.ac.cam.gpe21.droidssl.analysis.util;

import soot.RefType;

public final class Types {
	public static RefType STRING = RefType.v("java.lang.String");
	public static RefType SSL_SESSION = RefType.v("javax.net.ssl.SSLSession");
	public static RefType HOSTNAME_VERIFIER = RefType.v("javax.net.ssl.HostnameVerifier");

	private Types() {
		/* to prevent instantiation */
	}
}
