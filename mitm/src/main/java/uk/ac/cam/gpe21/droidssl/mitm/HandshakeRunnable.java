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
import java.util.logging.Level;
import java.util.logging.Logger;

public final class HandshakeRunnable implements Runnable {
	private static final Logger logger = Logger.getLogger(HandshakeRunnable.class.getName());

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
			SSLSocket secureOther = (SSLSocket) factory.createSocket(addr.getAddress(), addr.getPort());

			/*
			 * Normally the handshake is only started when reading or writing
			 * the first byte of data. However, we start it immediately so we
			 * can get the server's real certificate before we start relaying
			 * data between the server and client.
			 *
			 * We also detect if the handshake fails, and if so, fall back to
			 * forwarding the data directly (which will only let us intercept
			 * plaintext communication).
			 */
			boolean ssl;
			Socket other;
			try {
				secureOther.startHandshake();

				/*
				 * If we get here, the handshake worked. Use the working
				 * SSLSocket to relay the decrypted data.
				 */
				ssl = true;
				other = secureOther;
			} catch (IOException ex) {
				logger.log(Level.WARNING, "Handshake with destination failed, falling back to plaintext mode:", ex);

				/*
				 * If we get here, the SSL handshake failed. Open a normal
				 * socket to relay the data instead (which will probably be
				 * a protocol other than SSL - e.g. plaintext HTTP).
				 */
				ssl = false;
				other = new Socket(addr.getAddress(), addr.getPort());
			}

			IoCopyRunnable clientToServerCopier, serverToClientCopier;
			if (ssl) {
				/*
				 * Extract common name and subjectAltNames from the certificate.
				 */
				HostnameFinder hostnameFinder = server.getHostnameFinder();
				Certificate[] chain = secureOther.getSession().getPeerCertificates();
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
				 * Create IoCopyRunnables which operate on the intercepted
				 * decrypted data.
				 */
				clientToServerCopier = new IoCopyRunnable(secureSocket.getInputStream(), other.getOutputStream());
				serverToClientCopier = new IoCopyRunnable(other.getInputStream(), secureSocket.getOutputStream());
			} else {
				/*
				 * Create IoCopyRunnables which operate on the data sent
				 * between the sockets directly (which may or may not be
				 * plaintext).
				 */
				clientToServerCopier = new IoCopyRunnable(socket.getInputStream(), other.getOutputStream());
				serverToClientCopier = new IoCopyRunnable(other.getInputStream(), socket.getOutputStream());
			}

			/*
			 * Start two threads which relay data between the client and server
			 * in both directions, while dumping the data to the console.
			 */
			Executor executor = server.getExecutor();
			executor.execute(clientToServerCopier);
			executor.execute(serverToClientCopier);
		} catch (IOException ex) {
			// TODO ensure everything is closed upon failure and maybe log warnings
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
