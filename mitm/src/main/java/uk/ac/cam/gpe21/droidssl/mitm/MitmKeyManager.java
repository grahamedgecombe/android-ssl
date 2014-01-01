package uk.ac.cam.gpe21.droidssl.mitm;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateCache;
import uk.ac.cam.gpe21.droidssl.mitm.socket.factory.SocketFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public final class MitmKeyManager implements X509KeyManager {
	private final MitmServer server;
	private final InetSocketAddress sourceAddr, addr;
	private SSLSocket socket;
	private X509Certificate[] chain;

	public MitmKeyManager(MitmServer server, InetSocketAddress sourceAddr, InetSocketAddress addr) {
		this.server = server;
		this.sourceAddr = sourceAddr;
		this.addr = addr;
	}

	public Socket getSocket() {
		return socket;
	}

	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String chooseClientAlias(String[] keyType, Principal[] principals, Socket socket) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		return new String[] {
			"cert"
		};
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		if (!(socket instanceof SSLSocket))
			throw new IllegalArgumentException("socket is not an instance of SSLSocket");

		SSLSocket sslSocket = (SSLSocket) socket;
		SSLSession session = sslSocket.getHandshakeSession();

		String host = null;

		ExtendedSSLSession extendedSession = (ExtendedSSLSession) session;
		for (SNIServerName name : extendedSession.getRequestedServerNames()) {
			if (name.getType() == StandardConstants.SNI_HOST_NAME) {
				SNIHostName hostname = (SNIHostName) name;
				host = hostname.getAsciiName();
				break;
			}
		}

		try {
			SocketFactory socketFactory = server.getSocketFactory();
			if (host != null) {
				this.socket = socketFactory.openSslSocket(sourceAddr, addr, host);
			} else {
				this.socket = socketFactory.openSslSocket(sourceAddr, addr);
			}
			this.socket.startHandshake();

			CertificateCache certificateCache = server.getCertificateCache();
			chain = certificateCache.getChain(server, this.socket);
		} catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}

		return "cert";
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		if (!alias.equals("cert"))
			return null;

		return chain;
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		if (!alias.equals("cert"))
			return null;

		return server.getPrivateKey();
	}
}
