package uk.ac.cam.gpe21.droidssl.mitm;

import joptsimple.OptionParser;
import joptsimple.OptionSet;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.*;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.KeyPairGenerator;
import uk.ac.cam.gpe21.droidssl.mitm.socket.DestinationFinder;
import uk.ac.cam.gpe21.droidssl.mitm.socket.FixedDestinationFinder;
import uk.ac.cam.gpe21.droidssl.mitm.socket.NatDestinationFinder;
import uk.ac.cam.gpe21.droidssl.mitm.socket.StandardDestinationFinder;
import uk.ac.cam.gpe21.droidssl.mitm.util.SocketAddressParser;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class MitmServer {
	public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableKeyException, InvalidKeySpecException {
		OptionParser parser = new OptionParser();

		parser.accepts("fixed").withRequiredArg();
		parser.accepts("nat");
		parser.accepts("standard");

		parser.accepts("matching-hostname");
		parser.accepts("unmatching-hostname");

		parser.accepts("trusted");
		parser.accepts("untrusted");

		OptionSet set = parser.parse(args);

		DestinationFinder destinationFinder;
		if (set.has("fixed")) {
			String address = (String) set.valueOf("fixed");
			destinationFinder = new FixedDestinationFinder(SocketAddressParser.parse(address));
		} else if (set.has("nat")) {
			destinationFinder = new NatDestinationFinder();
		} else if (set.has("standard")) {
			destinationFinder = new StandardDestinationFinder();
		} else {
			System.err.println("Either --fixed, --nat or --standard must be specified.");
			System.exit(1);
			return;
		}

		HostnameFinder hostnameFinder;
		if (set.has("matching-hostname")) {
			hostnameFinder = new StandardHostnameFinder();
		} else if (set.has("unmatching-hostname")) {
			hostnameFinder = new FakeHostnameFinder();
		} else {
			System.err.println("Either --matching-hostname or --unmatching-hostname must be specified.");
			System.exit(1);
			return;
		}

		String caPrefix;
		if (set.has("trusted")) {
			caPrefix = "trusted";
		} else if (set.has("untrusted")) {
			caPrefix = "untrusted";
		} else {
			System.err.println("Either --trusted or --untrusted must be specified.");
			System.exit(1);
			return;
		}

		MitmServer server = new MitmServer(destinationFinder, hostnameFinder, caPrefix);
		server.start();
	}

	private final Executor executor = Executors.newCachedThreadPool();
	private final DestinationFinder destinationFinder;
	private final HostnameFinder hostnameFinder;
	private final CertificateAuthority certificateAuthority;
	private final CertificateGenerator certificateGenerator;
	private final Map<CertificateKey, X509Certificate> certificateCache = new HashMap<>();
	private final MitmKeyManager keyManager;
	private final SSLServerSocket serverSocket;
	private final SSLSocketFactory childFactory;

	public MitmServer(DestinationFinder destinationFinder, HostnameFinder hostnameFinder, String caPrefix) throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableKeyException, InvalidKeySpecException {
		this.destinationFinder = destinationFinder;
		this.hostnameFinder = hostnameFinder;

		this.certificateAuthority = new CertificateAuthority(Paths.get(caPrefix + ".crt"), Paths.get(caPrefix + ".key"));
		AsymmetricCipherKeyPair keyPair = new KeyPairGenerator().generate();
		this.certificateGenerator = new CertificateGenerator(certificateAuthority, keyPair);
		this.keyManager = new MitmKeyManager(certificateAuthority.getJcaCertificate(), KeyUtils.convertToJca(keyPair).getPrivate());

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(new KeyManager[] {
			keyManager
		}, null, null);
		this.serverSocket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(8443);

		SSLContext childContext = SSLContext.getInstance("TLS");
		childContext.init(null, new TrustManager[] {
			new PermissiveTrustManager()
		}, null);
		this.childFactory = childContext.getSocketFactory();
	}

	public void start() throws IOException, CertificateException {
		while (true) {
			SSLSocket socket = (SSLSocket) serverSocket.accept();

			/*
			 * Find the address of the target server and connect to it.
			 */
			InetSocketAddress addr = destinationFinder.getDestination(socket);
			SSLSocket other = (SSLSocket) childFactory.createSocket(addr.getAddress(), addr.getPort());

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
			X509Certificate fakeLeaf = certificateCache.get(key);
			if (fakeLeaf == null) {
				fakeLeaf = certificateGenerator.generateJca(key.getCn(), key.getSans());
				certificateCache.put(key, fakeLeaf);
			}

			/*
			 * Start the handshake with the client using the faked certificate.
			 */
			keyManager.setCertificate(socket, fakeLeaf);
			socket.startHandshake();

			/*
			 * Start two threads which relay data between the client and server
			 * in both directions, while dumping the decrypted data to the
			 * console.
			 */
			IoCopyRunnable clientToServerCopier = new IoCopyRunnable(socket.getInputStream(), other.getOutputStream());
			IoCopyRunnable serverToClientCopier = new IoCopyRunnable(other.getInputStream(), socket.getOutputStream());

			executor.execute(clientToServerCopier);
			executor.execute(serverToClientCopier);
		}
	}
}
