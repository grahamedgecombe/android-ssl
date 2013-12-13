package uk.ac.cam.gpe21.droidssl.mitm.testserver;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateUtils;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.key.KeyUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class TestServer {
	public static void main(String[] args) throws IOException, KeyManagementException, NoSuchAlgorithmException {
		System.setProperty("java.net.preferIPv4Stack" ,"true");

		X509Certificate leaf = CertificateUtils.readCertificate(Paths.get("cert.crt"));
		X509Certificate ca = CertificateUtils.readCertificate(Paths.get("ca.crt"));

		X509Certificate[] chain = new X509Certificate[] {
			leaf, ca
		};

		PrivateKey key = KeyUtils.readPrivateKey(Paths.get("cert.key"));

		KeyManager keyManager = new TestServerKeyManager(chain, key);

		TestServer server = new TestServer(keyManager);
		server.start();
	}

	private final Executor executor = Executors.newCachedThreadPool();
	private final SSLServerSocket serverSocket;

	public TestServer(KeyManager keyManager) throws NoSuchAlgorithmException, KeyManagementException, IOException {
		SSLContext context = SSLContext.getInstance("TLS");
		context.init(new KeyManager[] {
			keyManager
		}, null, null);
		this.serverSocket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(12345);
	}

	public void start() throws IOException {
		while (true) {
			SSLSocket socket = (SSLSocket) serverSocket.accept();
			executor.execute(new EchoRunnable(socket));
		}
	}
}
