package Digital_Signature_PDF;


import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.ProviderDigest;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class App 
{
	
	
	static PrivateKey  privateKey;
	static PublicKey publicKey;
    	static String inputFileName = "C:\\Users\\Hello\\Desktop\\contract.pdf";
    	static String outputFile = "C:\\Users\\Hello\\Desktop\\Digital-Signature.pdf"; 
    	static Certificate cert ;
    	static X509Certificate x509Certificate ;
    
    public static void main( String[] args ) 
    {
    	try {
		
		   	
		
		// Create instance of SunPKCS11 provider
     		String pkcs11Config = "C:\\Users\\\\Hello\\eclipse-workspace\\Digital_Signature_PDF\\config.cfg";
    		java.io.ByteArrayInputStream pkcs11ConfigStream = new java.io.ByteArrayInputStream(pkcs11Config.getBytes());
    		// Create a Provider for accessing the USB token by supplying the configuration.
	    	sun.security.pkcs11.SunPKCS11 providerPKCS11 = new sun.security.pkcs11.SunPKCS11(pkcs11Config);
	    	java.security.Security.addProvider(providerPKCS11);   

	   	// Create the Keystore for accessing certificates in the USB device by supplying the PIN.
	   	KeyStore.CallbackHandlerProtection chp = new KeyStore.CallbackHandlerProtection(new MyGuiCallbackHandler() {});
	    	KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", null, chp);
	    	KeyStore keyStore = builder.getKeyStore();
         
	    
	 
	    
	     	// Enumerate items (certificates and private keys) in the KeyStore
         	java.util.Enumeration<String> aliases = keyStore.aliases();	 
         	String alias = null;
		
		
		while (aliases.hasMoreElements()) {


		     alias = aliases.nextElement();


		     cert = keyStore.getCertificate(alias);
		     x509Certificate =  (X509Certificate)cert ;


		     // x509Certificate.getKeyUsage()[0]  Check whether the certificate has : digitalSignature         
		     if( x509Certificate.getKeyUsage()[0] == true) {

		     Key key = keyStore.getKey(alias, null); // Here I try to access the private key of my hardware certificate
		     privateKey  =  (PrivateKey )key ; 
		     publicKey = x509Certificate.getPublicKey();

		     break;

		     }     

		  }



		    // reader and stamper
		    PdfReader pdf = new PdfReader(inputFileName);
		    FileOutputStream fos = new FileOutputStream(outputFile);
		    PdfStamper stp = PdfStamper.createSignature(pdf, fos, '\0');
		    PdfSignatureAppearance sap = stp.getSignatureAppearance();
		    sap.setReason("Author Abdullah AlHussein");



		    // appearance
		    PdfSignatureAppearance appearance = stp .getSignatureAppearance();
		    appearance.setReason("Agreeing to the contract");
		    appearance.setLocation("Riyadh Saudi Arabia ");
		    appearance.setVisibleSignature(new Rectangle(72, 732, 250, 850), 1, "primeira assinatura");



		    // digital signature
		    ExternalSignature es = new PrivateKeySignature(privateKey, "SHA-1", providerPKCS11.getName());
		    ExternalDigest digest = new BouncyCastleDigest();
		    Certificate[] certs = new Certificate[1];
		    certs[0] = cert;

		    //Signs the document using the detached mode, CMS or CAdES equivalent
		    MakeSignature.signDetached(sap, digest, es, certs, null, null, null, 0, CryptoStandard.CMS);

		    System.out.println(" The PDF file has been signed successfully ");

			}
		
		catch(Exception e ) {
			
			e.printStackTrace();
			
		}
	
		
    }
}
