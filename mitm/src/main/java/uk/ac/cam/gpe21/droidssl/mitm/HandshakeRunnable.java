package uk.ac.cam.gpe21.droidssl.mitm;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.MitmKeyManager;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateCache;
import uk.ac.cam.gpe21.droidssl.mitm.socket.dest.DestinationFinder;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
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
			InetAddress ip = addr.getAddress();
			int port = addr.getPort();

			logger.info("Connecting to " + ip.getHostAddress() + ":" + port + " without SNI...");

			SSLSocketFactory factory = server.getPermissiveSocketFactory();
			SSLSocket secureOther = (SSLSocket) factory.createSocket(ip, port);

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
				 * Generate a fake certificate chain, using the same CN/SANs
				 * from the certificate found by connecting to the destination
				 * *without* SNI enabled.
				 */
				CertificateCache certificateCache = server.getCertificateCache();
				X509Certificate[] fakeChain = certificateCache.getChain(server, secureOther);

				/*
				 * Open an SSLSocket running on top of the socket between the
				 * client (i.e. the phone) and the MITM server (i.e. us), which
				 * will serve the certificate faked in the previous line.
				 */
				MitmKeyManager keyManager = new MitmKeyManager(server.getPrivateKey(), fakeChain);
				SSLSocket secureSocket = createSecureSocket(socket, keyManager);
				secureSocket.setUseClientMode(false);

				/*
				 * Add HostnameSniMatcher to this socket and start the
				 * handshake. This will detect if the client connected to the
				 * MITM server using SNI. If so, it opens another connection to
				 * the destination server *with* SNI enabled. If this is
				 * successful, it will replace the certificate currently set in
				 * the MitmKeyManager with one faked using the certificate
				 * found in the SNI connection to the destination (which could
				 * be different to the one found without SNI).
				 *
				 * Note: we had to grab the certificate served by the server
				 * without SNI before (rather than after) discovering if SNI is
				 * not used, because we will only know if SNI was used by the
				 * client *after* startHandshake() has returned, by which time
				 * we need to have already picked a certificate to serve to the
				 * client.
				 */
				HostnameSniMatcher sniMatcher = new HostnameSniMatcher(server, keyManager, addr);
				SSLParameters params = secureSocket.getSSLParameters();
				params.setSNIMatchers(Arrays.<SNIMatcher>asList(sniMatcher));
				secureSocket.setSSLParameters(params);

				secureSocket.startHandshake();

				/*
				 * If SNI was supported, we'll be connected to the real
				 * destination server on a different socket now, so we need to
				 * replace our reference to the destination server socket with
				 * the SNI-enabled one from HostnameSniMatcher.
				 */
				if (sniMatcher.isSniSupported()) {
					logger.info("SNI handshake successful, replaced socket with SNI socket.");
					other = sniMatcher.getSniSocket();
				}

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
			// TODO ensure everything is closed after a failure
			logger.log(Level.WARNING, "Handshake failed:", ex);
		}
	}

	private SSLSocket createSecureSocket(Socket socket, MitmKeyManager keyManager) throws IOException {
		// this is what the Sun SSLSocketImpl does for the host/port value
		String host = socket.getInetAddress().getHostAddress();
		int port = socket.getPort();

		try {
			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(new KeyManager[] {
				keyManager
			}, null, null);
			return (SSLSocket) ctx.getSocketFactory().createSocket(socket, host, port, true);
		} catch (NoSuchAlgorithmException | KeyManagementException ex) {
			throw new IOException(ex);
		}
	}
}
