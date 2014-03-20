package uk.ac.cam.gpe21.droidssl.mitm.crypto.hostname;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateKey;

import java.security.cert.X509Certificate;

public final class FakeHostnameFinder extends HostnameFinder {
	private final CertificateKey key = new CertificateKey("gpe21.pem.private.cam.ac.uk", new String[0]);

	@Override
	public CertificateKey getHostname(X509Certificate certificate) {
		return key;
	}

	@Override
	public String toString() {
		return "unmatching hostname";
	}
}
