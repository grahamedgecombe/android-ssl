package uk.ac.cam.gpe21.droidssl.mitm;

import com.sun.jna.ptr.IntByReference;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public final class MitmServer {
	public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableKeyException {
		//System.setProperty("javax.net.debug", "all");
		MitmServer server = new MitmServer();
		server.start();
	}

	private final Executor executor = Executors.newCachedThreadPool();
	private final String host = "encrypted.google.com";
	private final int port = 443;
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

	public void start() throws IOException {
		while (true) {
			SSLSocket socket = (SSLSocket) serverSocket.accept();

			int fd = FileDescriptors.getFd(socket);
			byte[] addr = new byte[28];
			int error = CLibrary.INSTANCE.getsockopt(fd, CLibrary.SOL_IP, CLibrary.SO_ORIGINAL_DST, addr, new IntByReference(addr.length));
			System.out.println(error + " " + Arrays.toString(addr));

			SSLSocket other = (SSLSocket) childFactory.createSocket(host, port);

			IoCopyRunnable clientToServerCopier = new IoCopyRunnable(socket.getInputStream(), other.getOutputStream());
			IoCopyRunnable serverToClientCopier = new IoCopyRunnable(other.getInputStream(), socket.getOutputStream());

			executor.execute(clientToServerCopier);
			executor.execute(serverToClientCopier);
		}
	}
}
