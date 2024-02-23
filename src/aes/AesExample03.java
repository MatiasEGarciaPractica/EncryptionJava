package aes;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author matia
 *	First check AesExample02
 * origin -> https://www.youtube.com/watch?v=L8LeYbztZxo&list=PLtgomJ95NvbPDMQClkBZPijLdEFyo0VHa&index=3
 * 
 * We import keys from diferents applications, in this case we get the keys from the AesExample02;
 * TO use import keys, we need the secretKey and the cipher IV.
 * 
 */
public class AesExample03 {

	private SecretKey key;
	private int T_LEN = 128;//The length of the authentication tag can be specified. It can be 128, 120, 112, 104, 96, 64, or 32 bits long. The longer the authentication tag, the stronger the security.
	private byte[] IV;
	
	public static void main(String[] args) {
		try {
			AesExample03 aes = new AesExample03();
			aes.initFromStrings("tiTqGzpyKin4qsZm5cC65A==", "54/XAAhUOZQD+Zaq"); //I get them from the AesExample02, but in real application we may get it from another app.
			String encryptedMessage = aes.encrypt("Coders");
			String decryptedMessage = aes.decrypt(encryptedMessage);
			
			
			System.err.println("Encrypted Message = " + encryptedMessage);
			System.err.println("Decrypted Message = " + decryptedMessage);
			//aes.exportKeys();
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * We set the keys from another app
	 * @param secretKey - secret key
	 * @param IV - cipher IV
	 */
	public void initFromStrings(String secretKey, String IV) {
		key = new SecretKeySpec(decode(secretKey), "AES");
		this.IV = decode(IV);
	}
	
	public String encrypt(String message) throws Exception {
		byte[] messageInBytes = message.getBytes();
		Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(T_LEN, IV);// important change, different fromAesExample02
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key, spec);
		IV = encryptionCipher.getIV();
		byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
		return encode(encryptedBytes);
	}

	public String decrypt(String encryptedMessage) throws Exception{
		byte[] messageInBytes = decode(encryptedMessage);
		Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(T_LEN, IV);//This ensures that the necessary parameters are set correctly for encryption and decryption operations. because we are using the same IV that encrypt
		decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
		byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
		return new String(decryptedBytes);
	}
	
	
	private void exportKeys() {
		System.err.println("SecretKey : " + encode(key.getEncoded()));
		System.err.println("IV : " + encode(IV));
	}
	
	

	private String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
	
	private byte[] decode(String data) {
		return Base64.getDecoder().decode(data);
	}
	
}
