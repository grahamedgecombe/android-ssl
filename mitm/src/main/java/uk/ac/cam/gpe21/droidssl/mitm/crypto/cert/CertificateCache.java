package uk.ac.cam.gpe21.droidssl.mitm.crypto.cert;

import uk.ac.cam.gpe21.droidssl.mitm.MitmServer;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.hostname.HostnameFinder;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.security.cert.Certificate;
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

	/**
	 * A higher-level wrapper around the {@link #get(CertificateKey)} method
	 * which also takes care of:
	 *
	 * <ul>
	 *     <li>Finding the Common Name and Subject Alt Names within the peer's
	 *         leaf certificate.</li>
	 *
	 *     <li>Generating a faked leaf certificate.</li>
	 *
	 *     <li>Generating the certificate chain (which consists of the fake
	 *         leaf certificate and the MITM server's fake CA certificate.)</li>
	 * </ul>
	 *
	 * @param server The {@link MitmServer}.
	 * @param socket The socket to extract the leaf certificate from.
	 * @return A {@link CertificateCacheResult}, which contains a faked
	 *         certificate chain.
	 * @throws SSLPeerUnverifiedException if {@link SSLSession#getPeerCertificates()} fails.
	 */
	public CertificateCacheResult getChain(MitmServer server, SSLSocket socket) throws SSLPeerUnverifiedException {
		HostnameFinder hostnameFinder = server.getHostnameFinder();
		X509Certificate fakeCa = server.getCertificateAuthority().getJcaCertificate();

		Certificate[] chain = socket.getSession().getPeerCertificates();
		X509Certificate leaf = (X509Certificate) chain[0];
		CertificateKey key = hostnameFinder.getHostname(leaf);

		X509Certificate fakeLeaf = get(key);

		return new CertificateCacheResult(key, new X509Certificate[] {
			fakeLeaf,
			fakeCa
		});
	}
}
