package uk.ac.cam.gpe21.droidssl.mitm;

import uk.ac.cam.gpe21.droidssl.mitm.socket.dest.DestinationFinder;
import uk.ac.cam.gpe21.droidssl.mitm.socket.factory.SocketFactory;
import uk.ac.cam.gpe21.droidssl.mitm.ui.Session;
import uk.ac.cam.gpe21.droidssl.mitm.ui.UserInterface;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
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
			 * Find the source address.
			 */
			InetSocketAddress sourceAddr = (InetSocketAddress) socket.getRemoteSocketAddress();

			/*
			 * Find the destination address.
			 */
			DestinationFinder destinationFinder = server.getDestinationFinder();
			InetSocketAddress addr = destinationFinder.getDestination(socket);
			InetAddress ip = addr.getAddress();
			int port = addr.getPort();

			logger.info("Accepted connection from " + sourceAddr + " -> " + addr);

			Session session = new Session(sourceAddr, addr); /* TODO */

			/*
			 * Check if the address is a loopback or local address, and if the
			 * port matches the port which the MITM server listens on. If so,
			 * we bail out to avoid causing an infinite loop of the MITM proxy
			 * connecting to itself over and over.
			 */
			boolean loopback = ip.isLoopbackAddress() || ip.isAnyLocalAddress();
			boolean portMatches = port == server.getServerSocket().getLocalPort();

			for (Enumeration<NetworkInterface> it = NetworkInterface.getNetworkInterfaces(); it.hasMoreElements();) {
				NetworkInterface dev = it.nextElement();
				for (Enumeration<InetAddress> it0 = dev.getInetAddresses(); it0.hasMoreElements();) {
					InetAddress devAddr = it0.nextElement();
					if (ip.equals(devAddr)) {
						loopback = true;
					}
				}
			}

			if (loopback && portMatches) {
				logger.warning("Closing connection to self...");
				socket.close();
				return;
			}

			/*
			 * Check if the destination server supports SSL or not. If it does
			 * not support SSL we fall back to copying the data directly which
			 * allows us to intercept plaintext communication (e.g. HTTP).
			 */
			boolean ssl = isSsl(addr);

			IoCopyRunnable clientToServerCopier, serverToClientCopier;
			UserInterface ui = server.getUserInterface();
			ui.onOpen(session);
			if (ssl) {
				/*
				 * Layer an SSLSocket on top of the socket between the source
				 * (i.e. the phone) and the MITM box (i.e. us).
				 */
				MitmKeyManager keyManager = new MitmKeyManager(server, sourceAddr, addr);
				SSLSocket secureSocket = createSecureSocket(socket, keyManager);
				secureSocket.setUseClientMode(false);

				/*
				 * Perform handshake with the phone. During the handshake, the
				 * MitmKeyManager will connect to the destination server,
				 * fetch the real certificate, create a faked certificate
				 * (possibly using the same CN/SAN, if --matching-hostname is
				 * set) and present the faked certificate to the client.
				 *
				 * After the handshake is complete we fetch the socket the
				 * MitmKeyManager made to the destination server so it can be
				 * used to shuttle data between the MITM box and the two
				 * endpoints (with the code directly below).
				 */
				secureSocket.startHandshake();
				Socket other = keyManager.getSocket();

				/*
				 * Update CertificateKey reference in the Session class. This
				 * allows the GUI to display the CN and SANs of the certificate
				 * (which in turn is useful for identifying the service being
				 * intercepted).
				 */
				session.setKey(keyManager.getKey());

				/*
				 * Create IoCopyRunnables which operate on the intercepted,
				 * decrypted data.
				 */
				clientToServerCopier = new IoCopyRunnable(session, true,  secureSocket.getInputStream(), other.getOutputStream(), ui);
				serverToClientCopier = new IoCopyRunnable(session, false, other.getInputStream(), secureSocket.getOutputStream(), ui);
			} else {
				/*
				 * Open plaintext socket to the destination server.
				 */
				SocketFactory socketFactory = server.getSocketFactory();
				Socket other = socketFactory.openSocket(sourceAddr, addr);

				/*
				 * Create IoCopyRunnables which operate on the data sent
				 * between the sockets directly (which may or may not be
				 * plaintext).
				 */
				clientToServerCopier = new IoCopyRunnable(session, true,  socket.getInputStream(), other.getOutputStream(), ui);
				serverToClientCopier = new IoCopyRunnable(session, false, other.getInputStream(), socket.getOutputStream(), ui);
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
			// TODO can we do anything about these in the GUI?
			logger.log(Level.WARNING, "Handshake failed:", ex);
		}
	}

	/**
	 * Checks if a remote server is running SSL by trying to start a handshake.
	 *
	 * NOTE: this method explicitly picks a random, local source address even
	 * if TPROXY mode is enabled. Otherwise, the socket will sometimes not
	 * close quickly enough, which leads to {@code bind()} on the second socket
	 * failing (even though {@code SO_REUSEADDR} is enabled).
	 * @param addr The destination address of the server to probe.
	 * @return {@code true} if the server is running SSL, {@code false} if not.
	 */
	private boolean isSsl(InetSocketAddress addr) {
		SocketFactory factory = server.getSocketFactory();
		try (SSLSocket socket = factory.openSslSocket(new InetSocketAddress(0), addr)) {
			socket.startHandshake();
			return true;
		} catch (IOException ex) {
			logger.log(Level.WARNING, "SSL handshake with destination failed:", ex);
			return false;
		}
	}

	/**
	 * Create an {@link SSLSocket}, layered above the given {@link Socket},
	 * which uses the given {@link MitmKeyManager}.
	 * @param socket The base socket.
	 * @param keyManager They key manager.
	 * @return An {@link SSLSocket} layered on top of the base socket.
	 * @throws IOException if an I/O error occurs, or if the socket could not
	 *                     be created due to a key or algorithm error.
	 */
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
