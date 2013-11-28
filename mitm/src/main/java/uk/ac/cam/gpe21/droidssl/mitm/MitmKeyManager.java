package uk.ac.cam.gpe21.droidssl.mitm;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public final class MitmKeyManager extends X509ExtendedKeyManager {
	private final X509Certificate caCertificate;
	private final PrivateKey key;
	private final Map<String, X509Certificate> certificates = new HashMap<>();

	public MitmKeyManager(X509Certificate caCertificate, PrivateKey key) {
		this.caCertificate = caCertificate;
		this.key = key;
	}

	private String getAlias(Socket socket) {
		return socket.getLocalSocketAddress().toString() + socket.getRemoteSocketAddress().toString();
	}

	public void setCertificate(SSLSocket socket, X509Certificate leafCertificate) {
		final String alias = getAlias(socket);
		synchronized (certificates) {
			certificates.put(alias, leafCertificate);
		}

		/*
		 * To avoid leaking memory, we remove the certificate from the map upon
		 * completion of the handshake.
		 * TODO check KeyManager won't be called after the handshake is done
		 * TODO check what happens if the handshake fails (e.g. socket closed)
		 */
		socket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
			@Override
			public void handshakeCompleted(HandshakeCompletedEvent event) {
				synchronized (certificates) {
					certificates.remove(alias);
				}
			}
		});
	}

	/* client-side functionality does not need to be implemented */
	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		throw new UnsupportedOperationException();
	}

	/* TODO do we need to implement this? */
	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		if (!(socket instanceof SSLSocket))
			throw new IllegalArgumentException("expecting socket to be an SSLSocket");

		if (!keyType.equals("RSA"))
			return null;

		return getAlias(socket);
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		X509Certificate certificate;
		synchronized (certificates) {
			certificate = certificates.get(alias);
		}

		if (certificate == null)
			throw new IllegalStateException("no certificate for alias: " + alias);

		return new X509Certificate[] {
			certificate, caCertificate
		};
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		return key;
	}
}
