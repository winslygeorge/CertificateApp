import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * 
 */

/**
 * @author georgos7
 *
 */
public class DeepCertServer {

	/**
	 * @param args
	 */
	static Socket client = null;
	static ServerSocket server = null;

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		try {
			server = new ServerSocket(3030);
			
			File file = new File("confid/keystore.jceks");
			
			if(!file.exists()) {
				
				GenerateRootCert cert = new GenerateRootCert();
				
				if(cert.configCert()== false) {
					server.close();
				}
			}else {
				
				KeyStore keystore = KeyStore.getInstance("jceks");
				
				keystore.load(new FileInputStream("confid/keystore.jceks"), "winslygay".toCharArray());
				
				if(keystore.containsAlias("rootPrivateKey")== false) {
					
					server.close();
				}
			}
			
			while(true) {
				
				client = server.accept();
				
				System.out.println("client is connected");
				
				ObjectInputStream in  = new ObjectInputStream( client.getInputStream());
				ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream());
				
				Thread runnable = new Thread() {
					
				
					public void run() {
						
						try {
							
						    if(!in.readUTF().equalsIgnoreCase("##reqcert>>")) {
						    	
						    	System.out.println("wrong cert request");
						    }else{
							
							Cert  obj = (Cert)in.readObject();
							
							if(obj !=null) {
											
								
															
								PublicKey publickey = obj.getKey();
								
								X509Certificate cert = new SignReceivedCertificate().sign(publickey, obj.getStr());
								
								
								
								KeyStore keystore = KeyStore.getInstance("jceks");
								
								keystore.load(new FileInputStream("confid/keystore.jceks"), "winslygay".toCharArray());
								
								X509Certificate rcert = (X509Certificate) keystore.getCertificateChain("rootPrivateKey")[0];
								
								
														
								out.writeObject(new Cert("sentCert", cert, rcert));
								out.flush();
								
								//byte [] outputarray = outarr.toByteArray();
								
								//out.println(outputarray);
							}else {
								
								System.out.println("obj was null");
							}
							
						    }
						
							in.close();
							//outarr.close();
					
					
					
							out.close();
							client.close();
						} catch (IOException | IllegalStateException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | SignatureException | KeyStoreException | CertificateException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						
					}
				};
				
				runnable.start();
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

	}
}
