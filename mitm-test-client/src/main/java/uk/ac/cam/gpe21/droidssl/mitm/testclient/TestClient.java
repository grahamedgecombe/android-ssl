package uk.ac.cam.gpe21.droidssl.mitm.testclient;

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
import java.security.cert.CertificateException;

public final class TestClient {
	public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException {
		TrustManager trustManager = new SecureTrustManager(CertificateUtils.readCertificate(Paths.get("ca.crt")));
		HostnameVerifier hostnameVerifier = new SecureHostnameVerifier();

		TestClient client = new TestClient(new InetSocketAddress("localhost", 12345), trustManager, hostnameVerifier);
		client.start();
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
			if (!hostnameVerifier.verify(address.getHostName(), socket.getSession()))
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
