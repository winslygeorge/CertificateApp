import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.MalformedURLException;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
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

public class GetCertUrl {

	/**
	 * @param args
	 */
	
	protected static File file = null;
	
public GetCertUrl (String hostname, int port, String user, String passwd) {
		// TODO Auto-generated method stub
		
		try {
			
			Socket client = new Socket(hostname, port);
			ObjectOutputStream  out = new ObjectOutputStream(client.getOutputStream());
			
			ObjectInputStream  in = new ObjectInputStream(client.getInputStream());
			
			KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
			
			keygen.initialize(4096, new SecureRandom());
			
			KeyPair key = keygen.generateKeyPair();
			
			file = new File("confid");
			if(!file.exists()) {

				file.mkdir();
			
				System.out.println("directory created");
				
			}
			
			
			
				out.writeObject(new Cert(user, key.getPublic()));
				out.flush();
				System.out.println("cert to sign sent");
				Cert ct = (Cert)in.readObject();
				
				
			System.out.println(ct.getRct());
			
			
			System.out.println(store(passwd, key.getPrivate(), ct.getCert(), ct.getRct()));
			
			
			in.close();
			out.close();
			client.close();

		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
public static boolean store(String userpasswd, PrivateKey key,X509Certificate certificate, X509Certificate certificate2) {
	
	boolean isconfigured = false;
	
	try {
		KeyStore keystore = KeyStore.getInstance("jceks");
		
		keystore.load(null, userpasswd.toCharArray());
		
		X509Certificate[] chain = new  X509Certificate[2];
		chain[0] = certificate;
		chain[1] = certificate2;
		
		char [] passcode = (userpasswd+"codd").toCharArray();
		keystore.setKeyEntry("userPrivateKey", key , passcode, chain );
		
		keystore.store(new FileOutputStream("confid/pirate.jceks") , userpasswd.toCharArray());
		
		if(keystore.size()!= 0||keystore.size()!=-1)
		{
		 isconfigured = true;
		}
	
	} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	
	return isconfigured;
	
	
}

}
