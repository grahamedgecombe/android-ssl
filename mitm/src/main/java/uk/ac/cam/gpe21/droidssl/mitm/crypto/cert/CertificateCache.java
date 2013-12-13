package uk.ac.cam.gpe21.droidssl.mitm.crypto.cert;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public final class CertificateCache {
	private final CertificateGenerator generator;
	private final Map<CertificateKey, X509Certificate> cache = new HashMap<>();

	public CertificateCache(CertificateGenerator generator) {
		this.generator = generator;
	}

	public synchronized X509Certificate get(CertificateKey key) {
		X509Certificate certificate = cache.get(key);
		if (certificate == null) {
			certificate = generator.generateJca(key.getCn(), key.getSans());
			cache.put(key, certificate);
		}
		return certificate;
	}
}
