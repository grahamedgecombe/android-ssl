package uk.ac.cam.gpe21.droidssl.mitm.testclient;

import joptsimple.OptionParser;
import joptsimple.OptionSet;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateUtils;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public final class TestClient {
	public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException {
		System.setProperty("java.net.preferIPv4Stack" ,"true");

		Certificate[] certificateAuthorities = {
			CertificateUtils.readCertificate(Paths.get("ca.crt")),
			CertificateUtils.readCertificate(Paths.get("trusted.crt"))
		};
		Certificate pinnedCertificate = CertificateUtils.readCertificate(Paths.get("cert.crt"));

		OptionParser parser = new OptionParser();

		parser.accepts("trusted");
		parser.accepts("untrusted");
		parser.accepts("pinned");

		parser.accepts("matching-hostname");
		parser.accepts("unmatching-hostname");

		OptionSet set = parser.parse(args);

		TrustManager trustManager;
		if (set.has("trusted")) {
			trustManager = new SecureTrustManager(certificateAuthorities);
		} else if (set.has("untrusted")) {
			trustManager = new PermissiveTrustManager();
		} else if (set.has("pinned")) {
			trustManager = new PinnedTrustManager((X509Certificate) pinnedCertificate); // TODO can we avoid the cast?
		} else {
			System.err.println("Either --trusted, --untrusted or --pinned must be specified.");
			System.exit(1);
			return;
		}

		HostnameVerifier hostnameVerifier;
		if (set.has("matching-hostname")) {
			hostnameVerifier = new SecureHostnameVerifier();
		} else if (set.has("unmatching-hostname")) {
			hostnameVerifier = new PermissiveHostnameVerifier();
		} else {
			System.err.println("Either --matching-hostname or --unmatching-hostname must be specified.");
			System.exit(1);
			return;
		}

		TestClient client = new TestClient(new InetSocketAddress("127.0.0.1", 12345), trustManager, hostnameVerifier);
		try {
			client.start();
		} catch (IOException ex) {
			ex.printStackTrace();
			System.exit(1); // to indicate the handshake failed
		}
	}

	private final InetSocketAddress address;
	private final HostnameVerifier hostnameVerifier;
	private final SSLSocketFactory factory;

	public TestClient(InetSocketAddress address, TrustManager trustManager, HostnameVerifier hostnameVerifier) throws NoSuchAlgorithmException, KeyManagementException {
		this.address = address;
		this.hostnameVerifier = hostnameVerifier;

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, new TrustManager[] {
			trustManager
		}, null);
		this.factory = context.getSocketFactory();
	}

	public void start() throws IOException {
		try (SSLSocket socket = (SSLSocket) factory.createSocket(address.getAddress(), address.getPort())) {
			socket.startHandshake();
			if (!hostnameVerifier.verify("localhost", socket.getSession()))
				throw new IOException();

			try (InputStream is = socket.getInputStream();
			     OutputStream os = socket.getOutputStream()) {
				os.write(0xFF);

				if (is.read() != 0xFF)
					throw new IOException("Server did not echo back 0xFF byte");
			}
		}
	}
}
