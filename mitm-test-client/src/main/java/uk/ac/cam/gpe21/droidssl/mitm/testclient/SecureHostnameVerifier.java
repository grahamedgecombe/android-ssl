package uk.ac.cam.gpe21.droidssl.mitm.testclient;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateUtils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public final class SecureHostnameVerifier implements HostnameVerifier {
	@Override
	public boolean verify(String hostname, SSLSession session) {
		try {
			Certificate[] chain = session.getPeerCertificates();
			X509Certificate leaf = (X509Certificate) chain[0];
			return hostname.equals(CertificateUtils.extractCn(leaf));
		} catch (SSLPeerUnverifiedException ex) {
			// TODO log warning?
			return false;
		}
	}
}
