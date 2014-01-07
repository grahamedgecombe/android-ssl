package uk.ac.cam.gpe21.droidssl.mitm.crypto;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public final class PermissiveTrustManager extends X509ExtendedTrustManager {
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		/* empty */
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		/* empty */
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return new X509Certificate[0];
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
		/* empty */
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
		/* empty */
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
		/* empty */
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
		/* empty */
	}
}
