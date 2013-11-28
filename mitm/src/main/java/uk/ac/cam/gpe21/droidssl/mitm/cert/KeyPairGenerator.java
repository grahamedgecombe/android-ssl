package uk.ac.cam.gpe21.droidssl.mitm.cert;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class KeyPairGenerator {
	private static final BigInteger PUBLIC_EXPONENT = new BigInteger("10001", 16); /* 65537 */
	private static final int KEY_LENGTH = 2048;

	public static KeyPair toJca(AsymmetricCipherKeyPair keyPair) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		SubjectPublicKeyInfo publicKey = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic());
		PrivateKeyInfo privateKey = PrivateKeyInfoFactory.createPrivateKeyInfo(keyPair.getPrivate());

		KeyFactory keyFactory = new DefaultJcaJceHelper().createKeyFactory("RSA"); // TODO should we really assume RSA?
		return new KeyPair(
			keyFactory.generatePublic(new X509EncodedKeySpec(publicKey.getEncoded())),
			keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey.getEncoded()))
		);
	}

	private final SecureRandom random = new SecureRandom();

	public AsymmetricCipherKeyPair generate() {
		RSAKeyPairGenerator keyGenerator = new RSAKeyPairGenerator();
		keyGenerator.init(new RSAKeyGenerationParameters(
			PUBLIC_EXPONENT, random, KEY_LENGTH, 95 /* certainty in % */
		));
		return keyGenerator.generateKeyPair();
	}
}
