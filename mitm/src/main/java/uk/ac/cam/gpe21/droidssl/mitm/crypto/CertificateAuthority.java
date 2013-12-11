package uk.ac.cam.gpe21.droidssl.mitm.crypto;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public final class CertificateAuthority {
	private final X509CertificateHolder certificate;
	private final X509Certificate jcaCertificate;
	private final AsymmetricKeyParameter publicKey;
	private final AsymmetricKeyParameter privateKey;

	public CertificateAuthority(Path certificateFile, Path keyFile) throws IOException, CertificateException {
		try (PEMParser parser = new PEMParser(Files.newBufferedReader(certificateFile, StandardCharsets.UTF_8))) {
			Object object = parser.readObject();
			if (!(object instanceof X509CertificateHolder))
				throw new IOException("Failed to read CA certificate file");

			certificate = (X509CertificateHolder) object;
			jcaCertificate = new JcaX509CertificateConverter().getCertificate(certificate);
		}

		try (PEMParser parser = new PEMParser(Files.newBufferedReader(keyFile, StandardCharsets.UTF_8))) {
			Object object = parser.readObject();
			if (!(object instanceof PEMKeyPair))
				throw new IOException("Failed to read CA key file");

			PEMKeyPair pair = (PEMKeyPair) object;
			publicKey = PublicKeyFactory.createKey(pair.getPublicKeyInfo());
			privateKey = PrivateKeyFactory.createKey(pair.getPrivateKeyInfo());
		}
	}

	public X509CertificateHolder getCertificate() {
		return certificate;
	}

	public X509Certificate getJcaCertificate() {
		return jcaCertificate;
	}

	public AsymmetricKeyParameter getPublicKey() {
		return publicKey;
	}

	public AsymmetricKeyParameter getPrivateKey() {
		return privateKey;
	}
}
