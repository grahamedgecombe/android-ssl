package uk.ac.cam.gpe21.droidssl.mitm.testclient;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public final class PinnedTrustManager implements X509TrustManager {
	private final X509Certificate certificate;

	public PinnedTrustManager(X509Certificate certificate) {
		this.certificate = certificate;
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		throw new CertificateException();
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		X509Certificate leaf = chain[0];
		leaf.checkValidity();

		boolean tbsCertificateEqual = Arrays.equals(certificate.getTBSCertificate(), leaf.getTBSCertificate());
		boolean signatureAlgorithmEqual = certificate.getSigAlgOID().equals(leaf.getSigAlgOID());
		boolean signatureEqual = Arrays.equals(certificate.getSignature(), leaf.getSignature());

		if (!(tbsCertificateEqual && signatureAlgorithmEqual && signatureEqual))
			throw new CertificateException();
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return new X509Certificate[0];
	}
}
