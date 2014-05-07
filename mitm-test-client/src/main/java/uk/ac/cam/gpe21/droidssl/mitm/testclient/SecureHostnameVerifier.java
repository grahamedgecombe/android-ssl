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

import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateUtils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public final class SecureHostnameVerifier implements HostnameVerifier {
	@Override
	public boolean verify(String hostname, SSLSession session) {
		try {
			Certificate[] chain = session.getPeerCertificates();
			X509Certificate leaf = (X509Certificate) chain[0];
			return hostname.equals(CertificateUtils.extractCn(leaf));
		} catch (SSLPeerUnverifiedException ex) {
			// TODO log warning?
			return false;
		}
	}
}
