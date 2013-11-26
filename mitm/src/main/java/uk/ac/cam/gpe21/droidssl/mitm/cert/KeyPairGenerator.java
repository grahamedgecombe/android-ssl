package uk.ac.cam.gpe21.droidssl.mitm.cert;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class KeyPairGenerator {
	private static final BigInteger PUBLIC_EXPONENT = new BigInteger("10001", 16); /* 65537 */
	private static final int KEY_LENGTH = 2048;

	private final SecureRandom random = new SecureRandom();

	public AsymmetricCipherKeyPair generate() {
		RSAKeyPairGenerator keyGenerator = new RSAKeyPairGenerator();
		keyGenerator.init(new RSAKeyGenerationParameters(
			PUBLIC_EXPONENT, random, KEY_LENGTH, 95 /* certainty in % */
		));
		return keyGenerator.generateKeyPair();
	}
}
