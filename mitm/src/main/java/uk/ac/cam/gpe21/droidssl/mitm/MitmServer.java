package uk.ac.cam.gpe21.droidssl.mitm;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import uk.ac.cam.gpe21.droidssl.mitm.cert.CertificateGenerator;
import uk.ac.cam.gpe21.droidssl.mitm.cert.CertificateKey;
import uk.ac.cam.gpe21.droidssl.mitm.cert.KeyPairGenerator;
import uk.ac.cam.gpe21.droidssl.mitm.socket.DestinationFinder;
import uk.ac.cam.gpe21.droidssl.mitm.socket.NatDestinationFinder;

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
		MitmServer server = new MitmServer();
		server.start();
	}

	private final Executor executor = Executors.newCachedThreadPool();
	private final DestinationFinder destinationFinder = new NatDestinationFinder();
	private final CertificateGenerator certificateGenerator;
	private final Map<CertificateKey, X509Certificate> certificateCache = new HashMap<>();
	private final MitmKeyManager keyManager;
	private final SSLServerSocket serverSocket;
	private final SSLSocketFactory childFactory;

	public MitmServer() throws NoSuchAlgorithmException, KeyManagementException, IOException, KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableKeyException, InvalidKeySpecException {
		KeyPairGenerator keyGenerator = new KeyPairGenerator();
		AsymmetricCipherKeyPair keyPair = keyGenerator.generate();

		this.certificateGenerator = new CertificateGenerator(Paths.get("ca.crt"), Paths.get("ca.key"), keyPair);

		this.keyManager = new MitmKeyManager(certificateGenerator.getCaCertificate(), KeyPairGenerator.toJca(keyPair).getPrivate());

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(new KeyManager[] {
			keyManager
		}, null, null);
		this.serverSocket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(8443);

		SSLContext childContext = SSLContext.getDefault();
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
			X500Name dn = JcaX500NameUtil.getSubject(leaf);
			String cn = null; // TODO extract into a method
			for (RDN rdn : dn.getRDNs()) {
				AttributeTypeAndValue first = rdn.getFirst();
				if (first.getType().equals(BCStyle.CN)) {
					cn = first.getValue().toString();
				}
			}
			if (cn == null)
				throw new IOException("DN has no CN!");
			String[] sans = new String[0]; // TODO extract

			/*
			 * Try to check if we have generated a certificate with the same CN
			 * & SANs already - if so, re-use it. (If we don't re-use it, e.g.
			 * a web browser thinks the certificate is different once we ignore
			 * the untrusted issuer error message, and we'll get another
			 * message to warn about the new certificate being untrusted ad
			 * infinitum).
			 */
			CertificateKey key = new CertificateKey(cn, sans);
			X509Certificate fakeLeaf = certificateCache.get(key);
			if (fakeLeaf == null) {
				fakeLeaf = certificateGenerator.generateJca(cn, sans);
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
