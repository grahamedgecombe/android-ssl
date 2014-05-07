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

package uk.ac.cam.gpe21.droidssl.mitm.crypto.hostname;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateKey;
import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateUtils;

import java.security.cert.X509Certificate;

public final class StandardHostnameFinder extends HostnameFinder {
	@Override
	public CertificateKey getHostname(X509Certificate certificate) {
		String cn = CertificateUtils.extractCn(certificate);
		String[] sans = CertificateUtils.extractSans(certificate);
		return new CertificateKey(cn, sans);
	}

	@Override
	public String toString() {
		return "matching hostname";
	}
}
