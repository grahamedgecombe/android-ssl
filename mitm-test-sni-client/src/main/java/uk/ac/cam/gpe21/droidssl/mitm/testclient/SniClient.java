package uk.ac.cam.gpe21.droidssl.mitm.testclient;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.PermissiveTrustManager;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateUtils;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public final class SniClient {
	public static void main(String[] args) throws KeyManagementException, NoSuchAlgorithmException, IOException {
		System.setProperty("java.net.preferIPv4Stack", "true");

		SniClient client = new SniClient(new InetSocketAddress("127.0.0.1", 12345), args[0]);
		client.start();
	}

	private final InetSocketAddress address;
	private final String host;
	private final SSLSocketFactory factory;

	public SniClient(InetSocketAddress address, String host) throws NoSuchAlgorithmException, KeyManagementException {
		this.address = address;
		this.host = host;

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, new TrustManager[] {
			new PermissiveTrustManager()
		}, null);
		this.factory = context.getSocketFactory();
	}

	public void start() throws IOException {
		InetAddress ip = address.getAddress();
		int port = address.getPort();

		try (SSLSocket socket = (SSLSocket) factory.createSocket(new Socket(ip, port), host, port, true)) {
			SSLParameters params = socket.getSSLParameters();
			params.setServerNames(Arrays.<SNIServerName>asList(new SNIHostName(host)));
			socket.setSSLParameters(params);

			socket.startHandshake();

			try (InputStream is = socket.getInputStream();
			     OutputStream os = socket.getOutputStream()) {
				os.write(0xFF);

				if (is.read() != 0xFF)
					throw new IOException("Server did not echo back 0xFF byte");
			}

			Certificate[] chain = socket.getSession().getPeerCertificates();
			X509Certificate leaf = (X509Certificate) chain[0];
			System.out.println(CertificateUtils.extractCn(leaf));
		}
	}
}
