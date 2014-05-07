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

import java.util.Arrays;

public final class CertificateKey {
	private final String cn;
	private final String[] sans;

	public CertificateKey(String cn, String[] sans) {
		this.cn = cn;
		this.sans = sans;
	}

	public String getCn() {
		return cn;
	}

	public String[] getSans() {
		return sans;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		CertificateKey that = (CertificateKey) o;

		if (!cn.equals(that.cn)) return false;
		if (!Arrays.equals(sans, that.sans)) return false;

		return true;
	}

	@Override
	public int hashCode() {
		int result = cn.hashCode();
		result = 31 * result + Arrays.hashCode(sans);
		return result;
	}
}
