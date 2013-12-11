package uk.ac.cam.gpe21.droidssl.mitm.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public final class CertificateGenerator {
	private static final TimeZone UTC = TimeZone.getTimeZone("Etc/UTC");

	private final CertificateAuthority ca;
	private final AsymmetricCipherKeyPair keyPair;
	private BigInteger serial = BigInteger.ZERO;

	public CertificateGenerator(CertificateAuthority ca, AsymmetricCipherKeyPair keyPair) throws IOException, CertificateException {
		this.ca = ca;
		this.keyPair = keyPair;
	}

	public X509Certificate generateJca(String cn, String[] sans) {
		try {
			JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
			X509CertificateHolder certificate = generate(cn, sans);
			return converter.getCertificate(certificate);
		} catch (CertificateException ex) {
			throw new CertificateGenerationException(ex);
		}
	}

	public X509CertificateHolder generate(String cn, String[] sans) {
		try {
			/* basic certificate structure */
			//serial = serial.add(BigInteger.ONE);
			// TODO: temporary workaround as reusing serial numbers makes Firefox complain
			serial = new BigInteger(Long.toString(System.currentTimeMillis()));

			Calendar notBefore = new GregorianCalendar(UTC);
			notBefore.add(Calendar.HOUR, -1);

			Calendar notAfter = new GregorianCalendar(UTC);
			notAfter.add(Calendar.HOUR, 24);

			X500Name subject = new X500NameBuilder().addRDN(BCStyle.CN, cn).build();

			BcX509ExtensionUtils utils = new BcX509ExtensionUtils();
			X509v3CertificateBuilder builder = new BcX509v3CertificateBuilder(ca.getCertificate(), serial, notBefore.getTime(), notAfter.getTime(), subject, keyPair.getPublic());

			/* subjectAlernativeName extension */
			if (sans.length > 0) {
				GeneralName[] names = new GeneralName[sans.length];
				for (int i = 0; i < names.length; i++) {
					names[i] = new GeneralName(GeneralName.dNSName, sans[i]);
				}
				builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
			}

			/* basicConstraints extension */
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

			/* subjectKeyIdentifier extension */
			builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(keyPair.getPublic()));

			/* authorityKeyIdentifier extension */
			builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(ca.getPublicKey()));

			/* keyUsage extension */
			int usage = KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement;
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));

			/* extendedKeyUsage extension */
			KeyPurposeId[] usages = { KeyPurposeId.id_kp_serverAuth };
			builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(usages));

			/* create the signer */
			AlgorithmIdentifier signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
			AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm);
			ContentSigner signer = new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(ca.getPrivateKey());

			/* build and sign the certificate */
			return builder.build(signer);
		} catch (IOException | OperatorCreationException ex) {
			throw new CertificateGenerationException(ex);
		}
	}
}
