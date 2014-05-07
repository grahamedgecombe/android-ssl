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

package uk.ac.cam.gpe21.droidssl.mitm.crypto.cert;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class CertificateUtils {
	private static final String[] EMPTY_STRING_ARRAY = new String[0];

	public static X509Certificate readCertificate(Path path) throws IOException {
		try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
			return readCertificate(reader);
		}
	}

	public static X509Certificate readCertificate(Reader reader) throws IOException {
		// TODO share with CertificateAuthority's own implementation
		try (PEMParser parser = new PEMParser(reader)) {
			Object object = parser.readObject();
			if (!(object instanceof X509CertificateHolder))
				throw new IOException("File does not contain a certificate");

			X509CertificateHolder certificate = (X509CertificateHolder) object;
			return new JcaX509CertificateConverter().getCertificate(certificate);
		} catch (CertificateException ex) {
			throw new IOException(ex);
		}
	}

	public static String extractCn(X509Certificate certificate) {
		X500Name dn = JcaX500NameUtil.getSubject(certificate);
		for (RDN rdn : dn.getRDNs()) {
			AttributeTypeAndValue first = rdn.getFirst();
			if (first.getType().equals(BCStyle.CN)) {
				return first.getValue().toString();
			}
		}

		throw new IllegalArgumentException("certificate subject has no common name (CN)");
	}

	public static String[] extractSans(X509Certificate certificate) {
		try {
			Collection<List<?>> pairs = certificate.getSubjectAlternativeNames();
			if (pairs == null)
				return EMPTY_STRING_ARRAY;

			List<String> sans = new ArrayList<>();
			for (List<?> pair : pairs) {
				int type = (Integer) pair.get(0);
				if (type == 2) { // TODO fix magic number!
					String san = (String) pair.get(1);
					sans.add(san);
				}
			}
			return sans.toArray(EMPTY_STRING_ARRAY);
		} catch (CertificateParsingException ex) {
			throw new IllegalArgumentException(ex); // TODO ideal?
		}
	}

	private CertificateUtils() {
		/* to prevent instantiation */
	}
}
