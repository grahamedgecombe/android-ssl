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

package uk.ac.cam.gpe21.droidssl.mitm.testclient;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public final class PinnedTrustManager implements X509TrustManager {
	private final X509Certificate certificate;

	public PinnedTrustManager(X509Certificate certificate) {
		this.certificate = certificate;
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		throw new CertificateException();
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		X509Certificate leaf = chain[0];
		leaf.checkValidity();

		boolean tbsCertificateEqual = Arrays.equals(certificate.getTBSCertificate(), leaf.getTBSCertificate());
		boolean signatureAlgorithmEqual = certificate.getSigAlgOID().equals(leaf.getSigAlgOID());
		boolean signatureEqual = Arrays.equals(certificate.getSignature(), leaf.getSignature());

		if (!(tbsCertificateEqual && signatureAlgorithmEqual && signatureEqual))
			throw new CertificateException();
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return new X509Certificate[0];
	}
}
