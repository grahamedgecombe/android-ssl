package uk.ac.cam.gpe21.droidssl.analysis.util;

import soot.ArrayType;
import soot.RefType;

public final class Types {
	public static final RefType STRING = RefType.v("java.lang.String");
	public static final ArrayType STRING_ARRAY = ArrayType.v(STRING, 1);

	public static final RefType ACTIVITY = RefType.v("android.app.Activity");
	public static final RefType VIEW = RefType.v("android.view.View");

	public static final RefType SSL_SESSION = RefType.v("javax.net.ssl.SSLSession");
	public static final RefType SSL_EXCEPTION = RefType.v("javax.net.ssl.SSLException");
	public static final RefType SSL_SOCKET_FACTORY = RefType.v("javax.net.ssl.SSLSocketFactory");
	public static final RefType SSL_CERTIFICATE_SOCKET_FACTORY = RefType.v("android.net.SSLCertificateSocketFactory");
	public static final RefType CERTIFICATE_EXCEPTION = RefType.v("java.security.cert.CertificateException");
	public static final RefType X509_CERTIFICATE = RefType.v("java.security.cert.X509Certificate");
	public static final ArrayType X509_CERTIFICATE_ARRAY = ArrayType.v(X509_CERTIFICATE, 1);

	public static final RefType HOSTNAME_VERIFIER = RefType.v("javax.net.ssl.HostnameVerifier");
	public static final RefType ABSTRACT_VERIFIER = RefType.v("org.apache.http.conn.ssl.AbstractVerifier");
	public static final RefType ALLOW_ALL_HOSTNAME_VERIFIER = RefType.v("org.apache.http.conn.ssl.AllowAllHostnameVerifier");

	public static final RefType APACHE_SSL_SOCKET_FACTORY = RefType.v("org.apache.http.conn.ssl.SSLSocketFactory");

	public static final RefType X509_TRUST_MANAGER = RefType.v("javax.net.ssl.X509TrustManager");

	public static final RefType HTTPS_URL_CONNECTION = RefType.v("javax.net.ssl.HttpsURLConnection");

	private Types() {
		/* to prevent instantiation */
	}
}
