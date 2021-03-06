/*
 * Copyright 2013-2014 Graham Edgecombe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.ac.cam.gpe21.droidssl.mitm;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateCache;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateCacheResult;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateKey;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.hostname.StandardHostnameFinder;
import uk.ac.cam.gpe21.droidssl.mitm.socket.factory.SocketFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public final class MitmKeyManager implements X509KeyManager {
	private final MitmServer server;
	private final StandardHostnameFinder realHostnameFinder = new StandardHostnameFinder();
	private final InetSocketAddress sourceAddr, addr;
	private SSLSocket socket;
	private X509Certificate[] chain;
	private CertificateKey realKey, key;

	public MitmKeyManager(MitmServer server, InetSocketAddress sourceAddr, InetSocketAddress addr) {
		this.server = server;
		this.sourceAddr = sourceAddr;
		this.addr = addr;
	}

	public SSLSocket getSocket() {
		return socket;
	}

	public CertificateKey getRealKey() {
		return realKey;
	}

	public CertificateKey getKey() {
		return key;
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

		/*
		 * Check if the client supplied a hostname with the SNI extension.
		 */
		ExtendedSSLSession extendedSession = (ExtendedSSLSession) session;
		for (SNIServerName name : extendedSession.getRequestedServerNames()) {
			if (name.getType() == StandardConstants.SNI_HOST_NAME) {
				SNIHostName hostname = (SNIHostName) name;
				host = hostname.getAsciiName();
				break;
			}
		}

		try {
			/*
			 * Connect to the destination server, possibly with SNI, then start
			 * the handshake.
			 */
			SocketFactory socketFactory = server.getSocketFactory();
			if (host != null) {
				this.socket = socketFactory.openSslSocket(sourceAddr, addr, host);
			} else {
				this.socket = socketFactory.openSslSocket(sourceAddr, addr);
			}
			this.socket.startHandshake();

			/*
			 * Find real CN/SANs.
			 */
			Certificate[] realChain = this.socket.getSession().getPeerCertificates(); // TODO de-dup with code in CertificateCache
			X509Certificate realLeaf = (X509Certificate) realChain[0];
			realKey = realHostnameFinder.getHostname(realLeaf);

			/*
			 * Generate a fake certificate.
			 */
			CertificateCache certificateCache = server.getCertificateCache();
			CertificateCacheResult result = certificateCache.getChain(server, this.socket);
			chain = result.getChain();
			key = result.getKey();
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
