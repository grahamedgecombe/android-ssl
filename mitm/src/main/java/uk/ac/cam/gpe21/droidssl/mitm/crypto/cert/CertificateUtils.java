package uk.ac.cam.gpe21.droidssl.mitm.crypto.cert;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public final class CertificateUtils {
	private static final String[] EMPTY_STRING_ARRAY = new String[0];

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
			List<String> sans = new ArrayList<>();
			for (List<?> pair : certificate.getSubjectAlternativeNames()) {
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
