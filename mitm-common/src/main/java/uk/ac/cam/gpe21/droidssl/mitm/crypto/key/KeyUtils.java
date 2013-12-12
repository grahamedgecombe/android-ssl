package uk.ac.cam.gpe21.droidssl.mitm.crypto.key;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class KeyUtils {
	public static PrivateKey readPrivateKey(Path path) throws IOException {
		try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
			return readPrivateKey(reader);
		}
	}

	public static PrivateKey readPrivateKey(Reader reader) throws IOException {
		try (PEMParser parser = new PEMParser(reader)) {
			Object object = parser.readObject();
			if (!(object instanceof PEMKeyPair))
				throw new IOException("File does not contain a key");

			PEMKeyPair pair = (PEMKeyPair) object;

			// TODO merge messy conversion logic with that below */
			AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(pair.getPrivateKeyInfo());
			PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey);
			KeyFactory keyFactory = new DefaultJcaJceHelper().createKeyFactory("RSA"); // TODO should we really assume RSA?
			return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
		} catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
			throw new IOException(ex);
		}
	}

	public static KeyPair convertToJca(AsymmetricCipherKeyPair keyPair) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		SubjectPublicKeyInfo publicKey = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic());
		PrivateKeyInfo privateKey = PrivateKeyInfoFactory.createPrivateKeyInfo(keyPair.getPrivate());

		KeyFactory keyFactory = new DefaultJcaJceHelper().createKeyFactory("RSA"); // TODO should we really assume RSA?
		return new KeyPair(
			keyFactory.generatePublic(new X509EncodedKeySpec(publicKey.getEncoded())),
			keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey.getEncoded()))
		);
	}

	private KeyUtils() {
		/* to prevent instantiation */
	}
}
