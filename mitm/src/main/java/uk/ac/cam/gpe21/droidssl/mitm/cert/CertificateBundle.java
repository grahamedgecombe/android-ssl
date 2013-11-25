package uk.ac.cam.gpe21.droidssl.mitm.cert;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

public final class CertificateBundle {
	private final X509CertificateHolder certificate;
	private final AsymmetricCipherKeyPair keyPair;

	public CertificateBundle(X509CertificateHolder certificate, AsymmetricCipherKeyPair keyPair) {
		this.certificate = certificate;
		this.keyPair = keyPair;
	}

	public X509CertificateHolder getCertificate() {
		return certificate;
	}

	public AsymmetricCipherKeyPair getKeyPair() {
		return keyPair;
	}
}
