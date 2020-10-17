

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.x509.X509V3CertificateGenerator;

@SuppressWarnings("deprecation")
public class GenCert{
	static Provider bc = new BouncyCastleProvider();
	
	static {
		
		Security.addProvider(bc);
	}
	
	protected X509V3CertificateGenerator cert = null;
	
	protected	X509Certificate certificate = null;
	
	
	
	public X509Certificate selfSignedCert (PublicKey key,PrivateKey pkey, String cnI, String cnS)  {
	
		
		
		try {

			X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
			
			cert.setIssuerDN(new X509Name("CN="+cnI));
			cert.setSerialNumber(BigInteger.valueOf((long) (Math.random()*100)));
			cert.setNotBefore(new Date(System.currentTimeMillis()-1000L * 60* 60*24*30 ));
			cert.setNotAfter(new Date(System.currentTimeMillis()+(1000l * 60*60*24*365*10)));
			
			cert.setPublicKey(key);
			cert.setSignatureAlgorithm("SHA256WithRSA");
			cert.setSubjectDN(new X509Name("CN="+cnS));
			cert.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(key));
			  cert.addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(key));
		        cert.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
		    	
			certificate = cert.generate(pkey);
				
				//System.out.println(certificate);
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
      
	
	
		return this.certificate;
			}
	
	  private static SubjectKeyIdentifier createSubjectKeyId(final PublicKey publicKey) throws OperatorCreationException, IOException {
		    final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		    
		    return new SubjectKeyIdentifier(publicKeyInfo.getEncoded());
		  }
	  
	  private static AuthorityKeyIdentifier createAuthorityKeyId(final PublicKey publicKey)
	      throws OperatorCreationException
	    {
	      final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
	         return new AuthorityKeyIdentifier(publicKeyInfo);
	    }
	
}