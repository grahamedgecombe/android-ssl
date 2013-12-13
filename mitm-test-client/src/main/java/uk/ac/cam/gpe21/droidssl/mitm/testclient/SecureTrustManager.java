package uk.ac.cam.gpe21.droidssl.mitm.testclient;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public final class SecureTrustManager implements X509TrustManager {
	private final X509TrustManager trustManager;

	public SecureTrustManager(Certificate[] certificateAuthorities) throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
		KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
		store.load(null);

		for (int i = 0; i < certificateAuthorities.length; i++) {
			store.setCertificateEntry("certificateAuthority" + i, certificateAuthorities[i]);
		}

		TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		factory.init(store);
		/* spec states the first X509TrustManager found in the array is used */
		for (TrustManager tm : factory.getTrustManagers()) {
			if (tm instanceof X509TrustManager) {
				trustManager = (X509TrustManager) tm;
				return;
			}
		}

		throw new RuntimeException("TrustManagerFactory did not return an X509TrustManager");
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		trustManager.checkClientTrusted(chain, authType);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		trustManager.checkServerTrusted(chain, authType);
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return trustManager.getAcceptedIssuers();
	}
}
