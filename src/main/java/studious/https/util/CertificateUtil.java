package studious.https.util;

import okhttp3.internal.tls.OkHostnameVerifier;
import studious.https.CertificateDetails;
import sun.security.util.UntrustedCertificates;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class CertificateUtil {

	public static CertificateDetails getCertificateDetails(String storeType, String jksPath, String jksPassword) {

		CertificateDetails certDetails = null;

		try {

			boolean isAliasWithPrivateKey = false;
			KeyStore keyStore = KeyStore.getInstance(storeType);

			// Provide location of Java Keystore and password for access
			keyStore.load(new FileInputStream(jksPath), jksPassword.toCharArray());

			// iterate over all aliases
			Enumeration<String> es = keyStore.aliases();
			String alias = "";
			while (es.hasMoreElements()) {
				alias = (String) es.nextElement();
				// if alias refers to a private key break at that point
				// as we want to use that certificate
				if (isAliasWithPrivateKey = keyStore.isKeyEntry(alias)) {
					break;
				}
			}

			if (isAliasWithPrivateKey) {

				KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
						new KeyStore.PasswordProtection(jksPassword.toCharArray()));

				PrivateKey myPrivateKey = pkEntry.getPrivateKey();

				// Load certificate chain
				Certificate[] chain = keyStore.getCertificateChain(alias);

				certDetails = new CertificateDetails();
				certDetails.setPrivateKey(myPrivateKey);
				certDetails.setX509Certificate((X509Certificate) chain[0]);

			}

		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			e.printStackTrace();
		}

		return certDetails;
	}

	public static boolean verifyHostname(String hostname, X509Certificate certificate) {
		return OkHostnameVerifier.INSTANCE.verify(hostname, certificate);
	}

	public static boolean isTrusted(X509Certificate certificate) {
		return !UntrustedCertificates.isUntrusted(certificate);
	}

}