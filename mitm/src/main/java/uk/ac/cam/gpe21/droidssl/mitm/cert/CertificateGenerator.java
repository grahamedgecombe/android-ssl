package uk.ac.cam.gpe21.droidssl.mitm.cert;

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
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public final class CertificateGenerator {
	public static void main(String[] args) throws IOException, CertificateException {
		KeyPairGenerator keyGenerator = new KeyPairGenerator();
		AsymmetricCipherKeyPair keyPair = keyGenerator.generate();

		CertificateGenerator generator = new CertificateGenerator(Paths.get("ca.crt"), Paths.get("ca.key"), keyPair);
		X509CertificateHolder certificate = generator.generate("google.com", new String[] { "www.google.com", "google.com" });

		try (PEMWriter writer = new PEMWriter(Files.newBufferedWriter(Paths.get("generated.crt"), StandardCharsets.UTF_8))) {
			writer.writeObject(certificate);
		}
	}

	private static final TimeZone UTC = TimeZone.getTimeZone("Etc/UTC");

	private final X509CertificateHolder caCertificate;
	private final X509Certificate jcaCaCertificate;
	private final AsymmetricKeyParameter caPublicKey;
	private final AsymmetricKeyParameter caPrivateKey;
	private final AsymmetricCipherKeyPair keyPair;
	private BigInteger serial = BigInteger.ZERO;

	public CertificateGenerator(Path caCertificateFile, Path caKeyFile, AsymmetricCipherKeyPair keyPair) throws IOException, CertificateException {
		this.keyPair = keyPair;

		try (PEMParser parser = new PEMParser(Files.newBufferedReader(caCertificateFile, StandardCharsets.UTF_8))) {
			Object object = parser.readObject();
			if (!(object instanceof X509CertificateHolder))
				throw new IOException("Failed to read CA certificate file");

			caCertificate = (X509CertificateHolder) object;
			jcaCaCertificate = new JcaX509CertificateConverter().getCertificate(caCertificate);
		}

		try (PEMParser parser = new PEMParser(Files.newBufferedReader(caKeyFile, StandardCharsets.UTF_8))) {
			Object object = parser.readObject();
			if (!(object instanceof PEMKeyPair))
				throw new IOException("Failed to read CA key file");

			PEMKeyPair pair = (PEMKeyPair) object;
			caPublicKey = PublicKeyFactory.createKey(pair.getPublicKeyInfo());
			caPrivateKey = PrivateKeyFactory.createKey(pair.getPrivateKeyInfo());
		}
	}

	public X509Certificate getCaCertificate() {
		return jcaCaCertificate;
	}

	public X509Certificate generateJca(String cn, String[] sans) throws CertificateException {
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		X509CertificateHolder certificate = generate(cn, sans);
		return converter.getCertificate(certificate);
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
			X509v3CertificateBuilder builder = new BcX509v3CertificateBuilder(caCertificate, serial, notBefore.getTime(), notAfter.getTime(), subject, keyPair.getPublic());

			/* subjectAlernativeName extension */
			if (sans.length > 0) {
				GeneralName[] names = new GeneralName[sans.length];
				for (int i = 0; i < names.length; i++) {
					names[i] = new GeneralName(GeneralName.dNSName, sans[i]);
				}
				builder.addExtension(X509Extension.subjectAlternativeName, false, new GeneralNames(names));
			}

			/* basicConstraints extension */
			builder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(false));

			/* subjectKeyIdentifier extension */
			builder.addExtension(X509Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(keyPair.getPublic()));

			/* authorityKeyIdentifier extension */
			builder.addExtension(X509Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(caPublicKey));

			/* keyUsage extension */
			int usage = KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement;
			builder.addExtension(X509Extension.keyUsage, true, new KeyUsage(usage));

			/* extendedKeyUsage extension */
			KeyPurposeId[] usages = { KeyPurposeId.id_kp_serverAuth };
			builder.addExtension(X509Extension.extendedKeyUsage, false, new ExtendedKeyUsage(usages));

			/* create the signer */
			AlgorithmIdentifier signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
			AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm);
			ContentSigner signer = new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(caPrivateKey);

			/* build and sign the certificate */
			return builder.build(signer);
		} catch (IOException | OperatorCreationException ex) {
			throw new CertificateGenerationException(ex);
		}
	}
}
