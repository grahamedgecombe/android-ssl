package uk.ac.cam.gpe21.droidssl.analysis.util;

import soot.ArrayType;
import soot.RefType;

public final class Types {
	public static RefType STRING = RefType.v("java.lang.String");
	public static ArrayType STRING_ARRAY = ArrayType.v(STRING, 1);

	public static RefType SSL_SESSION = RefType.v("javax.net.ssl.SSLSession");
	public static RefType SSL_EXCEPTION = RefType.v("javax.net.ssl.SSLException");

	public static RefType HOSTNAME_VERIFIER = RefType.v("javax.net.ssl.HostnameVerifier");
	public static RefType ABSTRACT_VERIFIER = RefType.v("org.apache.http.conn.ssl.AbstractVerifier");

	public static RefType X509_TRUST_MANAGER = RefType.v("javax.net.ssl.X509TrustManager");

	private Types() {
		/* to prevent instantiation */
	}
}
