package uk.ac.cam.gpe21.droidssl.mitm.crypto;

import java.security.cert.X509Certificate;

public abstract class HostnameFinder {
	public abstract CertificateKey getHostname(X509Certificate certificate);
}
