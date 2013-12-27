package uk.ac.cam.gpe21.droidssl.mitm.testserver;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public final class SniKeyManager implements X509KeyManager {
	private static final String[] EMPTY_STRING_ARRAY = new String[0];

	private final PrivateKey key;
	private final Map<String, X509Certificate[]> chains = new HashMap<>();

	public SniKeyManager(PrivateKey key) {
		this.key = key;
	}

	public void addChain(String hostname, X509Certificate[] chain) {
		chains.put(hostname, chain);
	}

	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		if (!keyType.equals("RSA"))
			return EMPTY_STRING_ARRAY;

		return chains.keySet().toArray(EMPTY_STRING_ARRAY);
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		if (!keyType.equals("RSA") || !(socket instanceof SSLSocket))
			return null;

		SSLSocket sslSocket = (SSLSocket) socket;
		SSLParameters params = sslSocket.getSSLParameters();

		Iterator<SNIMatcher> it = params.getSNIMatchers().iterator();
		if (!it.hasNext()) {
			return "default.example.com";
		}

		SniHostnameMatcher matcher = (SniHostnameMatcher) it.next();
		if (matcher.isSniEnabled()) {
			return matcher.getSniHostname();
		} else {
			return "default.example.com";
		}
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		return chains.get(alias);
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		if (!chains.containsKey(alias))
			return null;

		return key;
	}
}
