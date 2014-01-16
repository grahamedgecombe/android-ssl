package uk.ac.cam.gpe21.droidssl.mitm.crypto.cert;

import java.security.cert.X509Certificate;

public final class CertificateCacheResult {
	private final CertificateKey key;
	private final X509Certificate[] chain;

	public CertificateCacheResult(CertificateKey key, X509Certificate[] chain) {
		this.key = key;
		this.chain = chain;
	}

	public CertificateKey getKey() {
		return key;
	}

	public X509Certificate[] getChain() {
		return chain;
	}
}
