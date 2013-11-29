package uk.ac.cam.gpe21.droidssl.mitm.crypto;

import java.util.Arrays;

public final class CertificateKey {
	private final String cn;
	private final String[] sans;

	public CertificateKey(String cn, String[] sans) {
		this.cn = cn;
		this.sans = sans;
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
