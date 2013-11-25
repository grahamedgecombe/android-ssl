package uk.ac.cam.gpe21.droidssl.mitm;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class MitmServer {
	public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableKeyException {
		//System.setProperty("javax.net.debug", "all");
		MitmServer server = new MitmServer();
		server.start();
	}

	private final Executor executor = Executors.newCachedThreadPool();
	private final SSLServerSocket serverSocket;
	private final SSLSocketFactory childFactory;

	public MitmServer() throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableKeyException {
		KeyStore store = KeyStore.getInstance("JKS");
		try (InputStream is = new FileInputStream("cert.jks")) {
			store.load(is, "carrot".toCharArray());
		}

		KeyManagerFactory factory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
		factory.init(store, "carrot".toCharArray());
		KeyManager[] kms = factory.getKeyManagers();

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(kms, null, null);
		this.serverSocket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(8443);

		SSLContext childContext = SSLContext.getDefault();
		this.childFactory = childContext.getSocketFactory();
	}

	public void start() throws IOException, CertificateParsingException {
		while (true) {
			SSLSocket socket = (SSLSocket) serverSocket.accept();

			InetSocketAddress addr = Sockets.getOriginalDestination(socket);
			SSLSocket other = (SSLSocket) childFactory.createSocket(addr.getAddress(), addr.getPort());

			/*
			 * Normally the handshake is only started when reading or writing
			 * the first byte of data. However, we start it immediately to:
			 * - get the server's real certificate
			 * - create a fake certificate to present to the client
			 * - perform the handshake with the client
			 * and then at that point start relaying data between client and
			 * server.
			 */
			other.startHandshake();

			Certificate[] chain = other.getSession().getPeerCertificates();
			X509Certificate leaf = (X509Certificate) chain[0];
			System.out.println("DN=" + leaf.getSubjectX500Principal());
			System.out.println("SANs=" + leaf.getSubjectAlternativeNames());

			IoCopyRunnable clientToServerCopier = new IoCopyRunnable(socket.getInputStream(), other.getOutputStream());
			IoCopyRunnable serverToClientCopier = new IoCopyRunnable(other.getInputStream(), socket.getOutputStream());

			executor.execute(clientToServerCopier);
			executor.execute(serverToClientCopier);
		}
	}
}
