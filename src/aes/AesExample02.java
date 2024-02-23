package aes;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * 
 * @author matia
 *	Possible KEY_SIZE values are 128,192,256
 *	Possible T_LEN values are 128,112,104 and 96
 *	origin -> https://www.youtube.com/watch?v=J1RmZZEkN0k&list=PLtgomJ95NvbPDMQClkBZPijLdEFyo0VHa
 *
 *
 *	Creating key with KeyGenerator.
 * Encripting with Cipher.
 * Desencripting with Cipher and GCMParameterSpec
 *
 */
public class AesExample02 {

	private SecretKey key;
	private int KEY_SIZE = 128;
	private int T_LEN = 128;//The length of the authentication tag can be specified. It can be 128, 120, 112, 104, 96, 64, or 32 bits long. The longer the authentication tag, the stronger the security.
	private Cipher encryptionCipher;
	
	
	public static void main(String[] args) {
		try {
			AesExample02 aes = new AesExample02();
			aes.init();
			String encryptedMessage = aes.encrypt("Hello world!");
			String decryptedMessage = aes.decrypt(encryptedMessage);
			
			
			System.err.println("Encrypted Message = " + encryptedMessage);
			System.err.println("Decrypted Message = " + decryptedMessage);
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Generate key with AES Algorithm and with pre fixed size
	 * @throws Exception
	 */
	public void init() throws Exception{
		//generate keys for AES algorithm.
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(KEY_SIZE);
		key = generator.generateKey();	
	}
	
	public String encrypt(String message) throws Exception {
		byte[] messageInBytes = message.getBytes();
		encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
		return encode(encryptedBytes);
	}
	
	public String decrypt(String encryptedMessage) throws Exception{
		byte[] messageInBytes = decode(encryptedMessage);
		Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(T_LEN, encryptionCipher.getIV());//This ensures that the necessary parameters are set correctly for encryption and decryption operations. because we are using the same IV that encrypt
		decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
		byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
		return new String(decryptedBytes);
	}
	

	private String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
	
	private byte[] decode(String data) {
		return Base64.getDecoder().decode(data);
	}
	
}
