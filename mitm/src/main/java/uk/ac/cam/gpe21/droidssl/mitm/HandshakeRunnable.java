package uk.ac.cam.gpe21.droidssl.mitm;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.MitmKeyManager;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateCache;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateKey;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.hostname.HostnameFinder;
import uk.ac.cam.gpe21.droidssl.mitm.socket.dest.DestinationFinder;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.Executor;

public final class HandshakeRunnable implements Runnable {
	private final MitmServer server;
	private final Socket socket;

	public HandshakeRunnable(MitmServer server, Socket socket) {
		this.server = server;
		this.socket = socket;
	}

	@Override
	public void run() {
		try {
			/*
			 * Find the address of the target server and connect to it.
			 */
			DestinationFinder destinationFinder = server.getDestinationFinder();
			InetSocketAddress addr = destinationFinder.getDestination(socket);
			SSLSocketFactory factory = server.getPermissiveSocketFactory();
			SSLSocket other = (SSLSocket) factory.createSocket(addr.getAddress(), addr.getPort());

			/*
			 * Normally the handshake is only started when reading or writing
			 * the first byte of data. However, we start it immediately so we
			 * can get the server's real certificate before we start relaying
			 * data between the server and client.
			 */
			other.startHandshake();

			/*
			 * Extract common name and subjectAltNames from the certificate.
			 */
			HostnameFinder hostnameFinder = server.getHostnameFinder();
			Certificate[] chain = other.getSession().getPeerCertificates();
			X509Certificate leaf = (X509Certificate) chain[0];
			CertificateKey key = hostnameFinder.getHostname(leaf);

			/*
			 * Try to check if we have generated a certificate with the same CN
			 * & SANs already - if so, re-use it. (If we don't re-use it, e.g.
			 * a web browser thinks the certificate is different once we ignore
			 * the untrusted issuer error message, and we'll get another
			 * message to warn about the new certificate being untrusted ad
			 * infinitum).
			 */
			CertificateCache certificateCache = server.getCertificateCache();
			X509Certificate fakeLeaf = certificateCache.get(key);

			/*
			 * Start the handshake with the client using the faked certificate.
			 */
			SSLSocket secureSocket = createSecureSocket(socket, fakeLeaf);
			secureSocket.setUseClientMode(false);
			secureSocket.startHandshake();

			/*
			 * Start two threads which relay data between the client and server
			 * in both directions, while dumping the decrypted data to the
			 * console.
			 */
			IoCopyRunnable clientToServerCopier = new IoCopyRunnable(secureSocket.getInputStream(), other.getOutputStream());
			IoCopyRunnable serverToClientCopier = new IoCopyRunnable(other.getInputStream(), secureSocket.getOutputStream());

			Executor executor = server.getExecutor();
			executor.execute(clientToServerCopier);
			executor.execute(serverToClientCopier);
		} catch (IOException ex) {
			// TODO this is temporary to fix the tests
			// eventually we will want to be smarter (check if the
			// handshake for 'secureSocket' or 'other') failed and fall back to
			// just forwarding the bytes around directly if possible (e.g.
			// in case the destination server isn't actually using SSL but
			// is instead using plaintext communication)
		}
	}

	private SSLSocket createSecureSocket(Socket socket, X509Certificate certificate) throws IOException {
		// this is what the Sun SSLSocketImpl does for the host/port value
		String host = socket.getInetAddress().getHostAddress();
		int port = socket.getPort();

		X509Certificate[] chain = new X509Certificate[] {
			certificate,
			server.getCertificateAuthority().getJcaCertificate()
		};

		try {
			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(new KeyManager[] {
				new MitmKeyManager(chain, server.getPrivateKey())
			}, null, null);
			return (SSLSocket) ctx.getSocketFactory().createSocket(socket, host, port, true);
		} catch (NoSuchAlgorithmException | KeyManagementException ex) {
			throw new IOException(ex);
		}
	}
}
