import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * 
 */

/**
 * @author georgos7
 *
 */
public class GenerateRootCert{

	/**
	 * @param args
	 */
private boolean isconfigured;
	protected boolean  configCert () {
		// TODO Auto-generated method stub
		
		File file = new File("confid");
		
		if(!file.exists()) {
			
			file.mkdir();
			
			
			
			System.out.println("Directory created...");
			
		}

		//File fl = new File();
		
	
			
			try {
				
				KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
				
				keygen.initialize(4096, new SecureRandom());
				
				KeyPair key = keygen.generateKeyPair();
				
			
				
				
				X509Certificate cert = new GenCert().selfSignedCert(key.getPublic(), key.getPrivate(),"DeepDiveCA", "DeepDiveCA");
				
				X509Certificate[] chain = new X509Certificate[1];
				
				
			
				
				KeyStore keystore = KeyStore.getInstance("jceks");
				
				keystore.load(null, "winslygay".toCharArray());
				
				chain[0] = cert;
				
				keystore.setKeyEntry("rootPrivateKey", key.getPrivate() , "winslygay".toCharArray(), chain );
							
				keystore.store(new FileOutputStream("confid/keystore.jceks"), "winslygay".toCharArray());

				if(keystore.size()!= 0||keystore.size()!=-1)
					
					System.out.println("cert server all set up");
				{
					isconfigured = true;
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return isconfigured;
		

	}

}
