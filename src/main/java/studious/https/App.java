package studious.https;

import studious.https.util.*;


/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        CertificateDetails certDetails = CertificateUtil.getCertificateDetails("JKS",FileUtils.getBasePath()+"/https/san_domain_com.jks", "changeit");
        System.out.println(certDetails.getPrivateKey());
        System.out.println("--------------------------------");
//        System.out.println(certDetails.getX509Certificate());
        System.out.println(CertificateUtil.verifyHostname("127.0.0.1", certDetails.getX509Certificate()));
        System.out.println(CertificateUtil.verifyHostname("studious.lxz.com", certDetails.getX509Certificate()));

        System.out.println(CertificateUtil.isTrusted(certDetails.getX509Certificate()));

        CertificateDetails p12CertDetails = CertificateUtil.getCertificateDetails("PKCS12",FileUtils.getBasePath()+"/https/san_domain_com.p12", "changeit");
        System.out.println(CertificateUtil.verifyHostname("127.0.0.1", p12CertDetails.getX509Certificate()));
    }
}
