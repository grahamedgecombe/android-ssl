package uk.ac.cam.gpe21.droidssl.mitm;

import joptsimple.OptionParser;
import joptsimple.OptionSet;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.PermissiveTrustManager;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateAuthority;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateCache;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateGenerator;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.hostname.FakeHostnameFinder;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.hostname.HostnameFinder;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.hostname.StandardHostnameFinder;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.key.KeyPairGenerator;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.key.KeyUtils;
import uk.ac.cam.gpe21.droidssl.mitm.socket.dest.DestinationFinder;
import uk.ac.cam.gpe21.droidssl.mitm.socket.dest.FixedDestinationFinder;
import uk.ac.cam.gpe21.droidssl.mitm.socket.dest.NatDestinationFinder;
import uk.ac.cam.gpe21.droidssl.mitm.socket.dest.TproxyDestinationFinder;
import uk.ac.cam.gpe21.droidssl.mitm.util.SocketAddressParser;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class MitmServer {
	public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableKeyException, InvalidKeySpecException {
		OptionParser parser = new OptionParser();

		parser.accepts("fixed").withRequiredArg();
		parser.accepts("nat");
		parser.accepts("tproxy");

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
		} else if (set.has("tproxy")) {
			destinationFinder = new TproxyDestinationFinder();
		} else {
			System.err.println("Either --fixed, --nat or --tproxy must be specified.");
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
	private final AsymmetricCipherKeyPair keyPair;
	private final PrivateKey privateKey;
	private final CertificateCache certificateCache;
	private final ServerSocket serverSocket;
	private final SSLSocketFactory permissiveSocketFactory;

	public MitmServer(DestinationFinder destinationFinder, HostnameFinder hostnameFinder, String caPrefix) throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableKeyException, InvalidKeySpecException {
		this.destinationFinder = destinationFinder;
		this.hostnameFinder = hostnameFinder;
		this.certificateAuthority = new CertificateAuthority(Paths.get(caPrefix + ".crt"), Paths.get(caPrefix + ".key"));
		this.keyPair = new KeyPairGenerator().generate();
		this.privateKey = KeyUtils.convertToJca(keyPair).getPrivate();
		this.certificateCache = new CertificateCache(new CertificateGenerator(certificateAuthority, keyPair));
		this.serverSocket = destinationFinder.openUnboundServerSocket();
		this.permissiveSocketFactory = createPermissiveSocketFactory();
	}

	private SSLSocketFactory createPermissiveSocketFactory() throws KeyManagementException, NoSuchAlgorithmException {
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, new TrustManager[] {
			new PermissiveTrustManager()
		}, null);
		return ctx.getSocketFactory();
	}

	public void start() throws IOException, CertificateException {
		serverSocket.bind(new InetSocketAddress(8443));
		while (true) {
			Socket socket = serverSocket.accept();
			executor.execute(new HandshakeRunnable(this, socket));
		}
	}

	public Executor getExecutor() {
		return executor;
	}

	public DestinationFinder getDestinationFinder() {
		return destinationFinder;
	}

	public HostnameFinder getHostnameFinder() {
		return hostnameFinder;
	}

	public CertificateAuthority getCertificateAuthority() {
		return certificateAuthority;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public CertificateCache getCertificateCache() {
		return certificateCache;
	}

	public ServerSocket getServerSocket() {
		return serverSocket;
	}

	public SSLSocketFactory getPermissiveSocketFactory() {
		return permissiveSocketFactory;
	}
}
