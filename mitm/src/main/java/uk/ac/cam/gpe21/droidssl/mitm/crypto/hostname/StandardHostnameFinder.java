package uk.ac.cam.gpe21.droidssl.mitm.crypto.hostname;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateKey;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateUtils;

import java.security.cert.X509Certificate;

public final class StandardHostnameFinder extends HostnameFinder {
	@Override
	public CertificateKey getHostname(X509Certificate certificate) {
		String cn = CertificateUtils.extractCn(certificate);
		String[] sans = CertificateUtils.extractSans(certificate);
		return new CertificateKey(cn, sans);
	}

	@Override
	public String toString() {
		return "matching hostname";
	}
}
