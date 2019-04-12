package studious.https;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Set;
import java.util.regex.Pattern;

import static java.lang.System.*;

/**
 * Display 2 lines for every cert in cacerts.
 *
 * @author Roedy Green, Canadian Mind Products
 * @version 1.1 2016-07-04 sort and prune the display
 * @since 2012-12-20
 */
public class ShowRootCerts
    {
    /**
     * break file into lines at \n or \r\n
     */
    private static final Pattern LINE_SPLITTER = Pattern.compile( "\\r\\n|\\n", Pattern.MULTILINE );

    /**
     * display contents of cacerts file
     *
     * @param cacerts fully qualified name of cacerts file to display
     */
    private static void display( String cacerts )
        {
        try
            {
            out.println( cacerts );
            final FileInputStream fis = new FileInputStream( cacerts );
            final KeyStore keystore = KeyStore.getInstance( KeyStore.getDefaultType() );
            // must have set certspassword=changeit in environment.
            final String password = "changeit"; // by default changeit
            keystore.load( fis, password.toCharArray() );
            // This class retrieves the most-trusted CAs from the keystore
            final PKIXParameters params = new PKIXParameters( keystore );
            // Get the set of trust anchors, which contain the most-trusted CA certificates
            final Set<TrustAnchor> taset = params.getTrustAnchors();
            final X509Certificate[] certs = new X509Certificate[ taset.size() ];
            int j = 0;
            for ( TrustAnchor ta : taset )
                {
                certs[ j++ ] = ta.getTrustedCert();
                }
            Arrays.sort( certs, new CertificatesAlphabetically() );
            for ( X509Certificate cert : certs )
                {
                // Get certificate, actually sun.security.x509.X509CertImpl
                final String lump = cert.toString();
                // out.println( "{" + lump + "}" );
                // prume back the output
                final String[] lines = LINE_SPLITTER.split( lump );
                for ( String line : lines )
                    {
                    line = line.trim();
                    if ( line.startsWith( "Key:" ) || line.startsWith( "Subject:" ) )
                        {
                        out.println( line );
                        }
                    }
                out.println();
                }
            }
        catch ( Exception e )
            {
            err.println( e);
            }
        }

    /**
     * Display 2 lines for every cert in the java.home cacerts.
     * e
     *
     * @param optionals cacerts file.  If you leave off cacerts, you get java.home version
     *                  You can specify multiple cacerts: e.g.
     *                  C:\Program Files\Java\jre1.8.0_131\lib\security\cacerts
     *                  C:\Program Files (x86)\Java\jre1.8.0_131\lib\security\cacerts
     *                  F:\Program Files (x86)\jet11.3-pro-x86\bin\rt\lib\security\cacerts
     *                  E:\Program Files\Java\jdk1.8.0_131\jre\lib\security\cacerts    (java_home)
     *                  F:\Program Files (x86)\jet11.3-x86\profile1.8.0_101\jre\lib\security\cacerts
     *                  F:\Program Files (x86)\jet11.3-x86\setup\backup\ORIG\bin\rt\lib\security\cacerts
     *                  F:\Program Files\JetBrains\IntelliJ IDEA 2016.3\jre\jre\lib\security\cacerts
     */
    public static void main( String[] args )
        {
        // based on code posted at
        // http://stackoverflow.com/questions/3508050/how-can-i-get-a-list-of-trusted-root-certificates-in-java
        // Load the JDK's cacerts keystore file
        if ( args.length == 0 )
            {
            display( System.getProperty( "java.home" ) + "/lib/security/cacerts" );
            }
        else
            {
            for ( String arg : args )
                {
                display( arg );
                out.println( "----------------------" );
                }
            }
        }
    }
/*
 * [CertificatesAlphabetically.java]
 *
 * Summary: sort certificates alphabetically.
 *
 * Requires: JDK 1.8+.
 *
 * Java code generated with: Canadian Mind Products ComparatorCutter.
 *
 * Version History:
 *  1.0 2016-07-04 - initial release
 *
 */

/**
 * sort certificates alphabetically.
 * <p/>
 * Defines an alternate sort order for X509Certificate.
 *
 * @author Roedy Green
 * @version 1.0 2016-07-04 - initial release
 * @since 2016-07-04
 */
class CertificatesAlphabetically implements Comparator<X509Certificate>
    {
    /**
     * sort certificates alphabetically.
     * Defines an alternate sort order for X509Certificate
     * Compare two X509Certificate Objects.
     * Compares subject case sensitively.
     * Informally, returns (a-b), or +ve if a sorts after b.
     * <p>
     * Summary: sort certificates alphabetically.
     * <p>
     * Requires: JDK 1.8+.
     * <p>
     * Java code generated with: Canadian Mind Products ComparatorCutter.
     * <p>
     * Version History:
     * 1.0 2016-07-04 - initial release
     *
     * @param a first X509Certificate to compare
     * @param b second X509Certificate to compare
     *
     * @return +ve if a&gt;b, 0 if a==b, -ve if a&lt;b
     */
    public final int compare( X509Certificate a, X509Certificate b )
        {
        // look just after Subject: in string representation for comparables
        final String as = a.toString();
        final String bs = b.toString();
        int a1 = as.indexOf( "Subject: " );
        if ( a1 < 0 )
            {
            a1 = 0;
            }
        else
            {
            a1 += "Subject: ".length();
            }
        int b1 = bs.indexOf( "Subject: " );
        if ( b1 < 0 )
            {
            b1 = 0;
            }
        else
            {
            b1 += "Subject: ".length();
            }
        return as.substring( a1 ).compareTo( bs.substring( b1 ) );
        }
    }