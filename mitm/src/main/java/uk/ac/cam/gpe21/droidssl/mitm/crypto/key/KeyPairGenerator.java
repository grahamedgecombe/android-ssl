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

package uk.ac.cam.gpe21.droidssl.mitm.crypto.key;

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
