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
import uk.ac.cam.gpe21.droidssl.mitm.socket.factory.SocketFactory;
import uk.ac.cam.gpe21.droidssl.mitm.socket.factory.StandardSocketFactory;
import uk.ac.cam.gpe21.droidssl.mitm.socket.factory.TproxySocketFactory;
import uk.ac.cam.gpe21.droidssl.mitm.ui.gui.GraphicalUserInterface;
import uk.ac.cam.gpe21.droidssl.mitm.ui.headless.HeadlessUserInterface;
import uk.ac.cam.gpe21.droidssl.mitm.ui.UserInterface;
import uk.ac.cam.gpe21.droidssl.mitm.util.SocketAddressParser;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
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
	private static SSLSocketFactory createPermissiveSocketFactory() throws KeyManagementException, NoSuchAlgorithmException {
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, new TrustManager[] {
			new PermissiveTrustManager()
		}, null);
		return ctx.getSocketFactory();
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableKeyException, InvalidKeySpecException, InvocationTargetException, InterruptedException {
		OptionParser parser = new OptionParser();

		parser.accepts("title").withRequiredArg().defaultsTo("<untitled>");

		parser.accepts("port").withRequiredArg().ofType(int.class).defaultsTo(8443);

		parser.accepts("fixed").withRequiredArg();
		parser.accepts("nat");
		parser.accepts("tproxy");

		parser.accepts("matching-hostname");
		parser.accepts("unmatching-hostname");

		parser.accepts("trusted");
		parser.accepts("untrusted");

		parser.accepts("gui");

		OptionSet set = parser.parse(args);

		SSLSocketFactory sslSocketFactory = createPermissiveSocketFactory();

		SocketFactory socketFactory;
		DestinationFinder destinationFinder;
		if (set.has("fixed")) {
			String address = (String) set.valueOf("fixed");
			socketFactory = new StandardSocketFactory(sslSocketFactory);
			destinationFinder = new FixedDestinationFinder(SocketAddressParser.parse(address));
		} else if (set.has("nat")) {
			socketFactory = new StandardSocketFactory(sslSocketFactory);
			destinationFinder = new NatDestinationFinder();
		} else if (set.has("tproxy")) {
			socketFactory = new TproxySocketFactory(sslSocketFactory);
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

		UserInterface ui;
		if (set.has("gui")) {
			ui = new GraphicalUserInterface();
		} else {
			ui = new HeadlessUserInterface();
		}

		String title = (String) set.valueOf("title");
		int port = (int) set.valueOf("port");

		MitmServer server = new MitmServer(title, port, socketFactory, destinationFinder, hostnameFinder, caPrefix, ui);
		server.start();
	}

	private final Executor executor = Executors.newCachedThreadPool();
	private final String title;
	private final SocketFactory socketFactory;
	private final DestinationFinder destinationFinder;
	private final HostnameFinder hostnameFinder;
	private final UserInterface userInterface;
	private final CertificateAuthority certificateAuthority;
	private final AsymmetricCipherKeyPair keyPair;
	private final PrivateKey privateKey;
	private final CertificateCache certificateCache;
	private final ServerSocket serverSocket;

	public MitmServer(String title, int port, SocketFactory socketFactory, DestinationFinder destinationFinder, HostnameFinder hostnameFinder, String caPrefix, UserInterface userInterface) throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableKeyException, InvalidKeySpecException {
		this.title = title;
		this.socketFactory = socketFactory;
		this.destinationFinder = destinationFinder;
		this.hostnameFinder = hostnameFinder;
		this.userInterface = userInterface;
		this.userInterface.init(title, caPrefix, hostnameFinder.toString());
		this.certificateAuthority = new CertificateAuthority(Paths.get(caPrefix + ".crt"), Paths.get(caPrefix + ".key"));
		this.keyPair = new KeyPairGenerator().generate();
		this.privateKey = KeyUtils.convertToJca(keyPair).getPrivate();
		this.certificateCache = new CertificateCache(new CertificateGenerator(certificateAuthority, keyPair));
		this.serverSocket = socketFactory.openServerSocket(new InetSocketAddress(port));
	}

	public void start() throws IOException, CertificateException {
		while (true) {
			Socket socket = serverSocket.accept();
			executor.execute(new HandshakeRunnable(this, socket));
		}
	}

	public Executor getExecutor() {
		return executor;
	}

	public SocketFactory getSocketFactory() {
		return socketFactory;
	}

	public DestinationFinder getDestinationFinder() {
		return destinationFinder;
	}

	public HostnameFinder getHostnameFinder() {
		return hostnameFinder;
	}

	public UserInterface getUserInterface() {
		return userInterface;
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
}
