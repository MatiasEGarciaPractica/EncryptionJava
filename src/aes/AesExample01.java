package aes;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
//origin -> https://www.youtube.com/watch?v=E0T7-fXUM3c

/**
 * 
 * @author matia
 * Crear llave con ScretKeySpec y MessageDigest, encriptar y desencriptar con Cipher 
 */
public class AesExample01 {
	
	static final String LLAVE = "SomosProgramadores";
	
	public static void main(String[] args) {
		String encriptada = "";
		String aEncriptar = "";
		
		aEncriptar = JOptionPane.showInputDialog("Ingrese la cadena a encriptar");
		encriptada = Encriptar(aEncriptar);
		JOptionPane.showMessageDialog(null, encriptada);
		JOptionPane.showMessageDialog(null, Desencriptar(encriptada));
		
	}
	
	public static SecretKeySpec CrearClave(String llave) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(llave.getBytes());
			byte[] digestedKey = md.digest();
			
			// the SHA-1 algorithm produces a hash of 20 bytes, which is longer than the required 16 bytes for the AES key. So we set the length with copyOf.
			digestedKey = Arrays.copyOf(digestedKey, 16);
			SecretKeySpec secretKeySpec = new SecretKeySpec(digestedKey, "AES");
			return secretKeySpec;
		}catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static String Encriptar(String encriptar) {
		try {
            //cipher : used for encryption and decryption operations. It provides functionality 
			//for encrypting and decrypting data using various encryption algorithms, such as AES 
			//(Advanced Encryption Standard), DES (Data Encryption Standard), and RSA (Rivest-Shamir-Adleman).
			SecretKeySpec secretKeySpec = CrearClave(LLAVE);
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			
			byte [] cadena = encriptar.getBytes("UTF-8");
			byte [] encriptada = cipher.doFinal(cadena);
			String cadena_encriptada = Base64.getEncoder().encodeToString(encriptada);
			return cadena_encriptada;
		}catch(Exception e) {
			e.printStackTrace();
			return "";
		}
	}
	
	public static String Desencriptar(String desencriptar) {
		try {
            //cipher
			SecretKeySpec secretKeySpec = CrearClave(LLAVE);
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			
			byte [] cadena = Base64.getDecoder().decode(desencriptar);
			byte [] desencriptation = cipher.doFinal(cadena);
			return new String(desencriptation);
		}catch(Exception e) {
			e.printStackTrace();
			return "";
		}
	}
	
}
