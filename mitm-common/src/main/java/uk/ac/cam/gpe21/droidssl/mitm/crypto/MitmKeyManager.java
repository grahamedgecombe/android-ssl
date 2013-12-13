package uk.ac.cam.gpe21.droidssl.mitm.crypto;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public final class MitmKeyManager implements X509KeyManager {
	private final X509Certificate[] chain;
	private final PrivateKey key;

	public MitmKeyManager(X509Certificate[] chain, PrivateKey key) {
		this.chain = chain;
		this.key = key;
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
			return new String[0];

		return new String[] {
			"cert"
		};
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		if (!keyType.equals("RSA"))
			return null;

		return "cert";
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		return chain;
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		return key;
	}
}
