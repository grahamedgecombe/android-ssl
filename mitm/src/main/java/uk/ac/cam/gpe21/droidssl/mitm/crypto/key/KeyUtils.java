package uk.ac.cam.gpe21.droidssl.mitm.crypto.key;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class KeyUtils {
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
