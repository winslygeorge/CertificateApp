import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * 
 */

/**
 * @author georgos7
 *
 */
public class SignReceivedCertificate {
	

	private PrivateKey key = null;
	
	private X509Certificate certificate = null;
	
	public X509Certificate sign(PublicKey k,String issuerName) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException {

		
		
		try {
			KeyStore keystore = KeyStore.getInstance("jceks");
			
			keystore.load(new FileInputStream("confid/keystore.jceks"), "winslygay".toCharArray());
			
		key = (PrivateKey) keystore.getKey("rootPrivateKey", "winslygay".toCharArray());
		
		
		certificate = new GenCert().selfSignedCert(k, key, "DeepDiveCA", issuerName);
			
		
			
		} catch (IllegalStateException | NoSuchAlgorithmException
				| KeyStoreException | CertificateException | IOException | UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return certificate;
	}

}
