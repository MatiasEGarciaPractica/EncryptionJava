package des;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author matia
 * First see class DesExample01
 * Origin -> https://www.youtube.com/watch?v=ZO4FlQBWIm4&list=PLtgomJ95NvbPDMQClkBZPijLdEFyo0VHa&index=5
 * 
 * Now with the key and Iv from anohter Chipher, I mean we import those values and we use to encrypt the message and desencrypt.
 * 
 */
public class DesExample02 {

	private static final String  KEY_STRING = "9ztJGQuKnj0="; //this value I get it from DesExample01, but you will get it from another app.
	private static final String  IV_STRING = "U1Zw27idkW8="; //this value I get it from DesExample01, but you will get it from another app.
	private final SecretKey key;
	private Cipher encCipher;
	private Cipher decCipher;
	
	public static void main(String[] args) {
		String message = "The coders";
		try {
			DesExample02 des = new DesExample02();
			
			byte[] encryptedBytes = des.encrypt(message);
			String encodedMessage = encode(encryptedBytes);
			System.out.println("Encrypted message with imported key: " +	encodedMessage);
			byte[] decodedMessage = decode(encodedMessage);
			System.out.println("Decrypted message : " + des.decrypt(decodedMessage));
		}catch(Exception e) {
			e.printStackTrace();
		}
		
	}
	
	
	public DesExample02() throws Exception{
		this.key = generateKey();
		initCiphersCBC();
	}
	
	
	/**
	 * This needs encCipher IV.
	 * @throws Exception
	 */
	private void initCiphersCBC() throws Exception{
		encCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		decCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		encCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(decode(IV_STRING)));//imported cipher IV
		decCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(decode(IV_STRING)));//imported cipher IV
	}

	
	public byte[] encrypt(String message) throws Exception{
		return encCipher.doFinal(message.getBytes());
	}
	public String decrypt(byte[] encryptedMessage) throws Exception {
		byte[] decryptedMessage = decCipher.doFinal(encryptedMessage);
		return new String(decryptedMessage);
	}
	
	
	/**
	 * Generate a key from a string key imported.
	 * @return
	 */
	public static SecretKey generateKey(){
		return new SecretKeySpec(decode(KEY_STRING),"DES");//imported DES key
	}
	
	public static String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
	
	public static byte[] decode(String data) {
		return Base64.getDecoder().decode(data);
	}
}
