package uk.ac.cam.gpe21.droidssl.mitm;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.MitmKeyManager;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateCache;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class HostnameSniMatcher extends SNIMatcher {
	private static final Logger logger = Logger.getLogger(HostnameSniMatcher.class.getName());

	private final MitmServer server;
	private final MitmKeyManager keyManager;
	private final InetSocketAddress sourceAddress;
	private final InetSocketAddress address;
	private SSLSocket sniSocket;

	public HostnameSniMatcher(MitmServer server, MitmKeyManager keyManager, InetSocketAddress sourceAddress, InetSocketAddress address) {
		super(StandardConstants.SNI_HOST_NAME);
		this.server = server;
		this.keyManager = keyManager;
		this.sourceAddress = sourceAddress;
		this.address = address;
	}

	// TODO check what happens if the client sends multiple SNIServerNames? is this possible?
	@Override
	public boolean matches(SNIServerName name) {
		SNIHostName hostname = (SNIHostName) name;

		InetAddress ip = address.getAddress();
		int port = address.getPort();
		String host = hostname.getAsciiName();

		logger.info("Connecting to " + ip.getHostAddress() + ":" + port + " with SNI (host = " + host + ")...");
		try {
			/*
			 * Connect to the destination IP/port with SNI enabled (passing
			 * through the original client's SNI request).
			 */
			SSLSocket socket = server.getSocketFactory().openSslSocket(sourceAddress, address, host);

			SSLParameters params = socket.getSSLParameters();
			params.setServerNames(Collections.singletonList(name));
			socket.setSSLParameters(params);

			socket.startHandshake();

			/*
			 * If we get this far past the handshake, the connection worked.
			 * Generate and set a new fake certificate chain, to override the
			 * non-SNI fake certificate. We also set sniSocket to the working
			 * socket (as opposed to null), so that HandshakeRunnable can
			 * replace its own reference to the SNI-disabled socket with the
			 * SNI-enabled socket.
			 */
			CertificateCache certificateCache = server.getCertificateCache();
			X509Certificate[] fakeChain = certificateCache.getChain(server, socket);
			keyManager.setChain(fakeChain);

			sniSocket = socket;
			return true;
		} catch (IOException ex) {
			logger.log(Level.WARNING, "SNI handshake failed, falling back to non-SNI socket...", ex);

			/*
			 * We return true despite failure because we want the connection
			 * between the client and the MITM server to succeed (if false is
			 * returned, the unrecognized_name SSL alert is sent by Java's SSL
			 * implementation, which ultimately causes the connection to
			 * be terminated).
			 *
			 * Instead, if failure does happen, we simply skip the code to swap
			 * the fake certificate chain and the sniSocket over, meaning the
			 * code in HandshakeRunnable carries on using the working non-SNI
			 * socket.
			 */
			return true;
		}
	}

	public boolean isSniSupported() {
		return sniSocket != null;
	}

	public SSLSocket getSniSocket() {
		return sniSocket;
	}
}
