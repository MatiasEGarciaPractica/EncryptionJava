package rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

/**
 * 
 * @author matia
 *	
 * AES/CBC/NoPadding(128)
 * AES/CBC/PKCSSPaddig(128)
 * AES/ECB/NoPadding(128)
 * AES/ECB/PKCSSPadding(128)
 * RSA/ECB/PKCS1Padding(1024,2048)
 * RSA/ECB/OAEPWithSHA-1AndMGF1Padding(1024,2048)
 * RSA/ECB/OAEPWithSHA-256AndMGF1Padding(1024,2048)
 * 
 * Origin -> https://www.youtube.com/watch?v=R9eerqP78PE&list=PLtgomJ95NvbPDMQClkBZPijLdEFyo0VHa&index=3
 * 
 * Encrypting and Decrypting Strings with RSA key(pair key, public and private).
 * 
 */
public class RsaExample01 {
	
	private PrivateKey privateKey;
	private PublicKey publicKey;
	
	
	public static void main(String[] args) {
		RsaExample01 rsa = new RsaExample01();
		try {
			String encryptedMessage = rsa.encrypt("Hello world");
			String decryptMessage = rsa.decrypt(encryptedMessage);
			
			System.err.println("Encrypted: \n" + encryptedMessage);
			System.err.println("Decrypted: \n" + decryptMessage);
			rsa.printKeys();
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public RsaExample01() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);
			KeyPair pair = generator.generateKeyPair();
			privateKey = pair.getPrivate();
			publicKey = pair.getPublic();
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public String encrypt(String message) throws Exception{
		byte[] messageToBytes = message.getBytes();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedBytes = cipher.doFinal(messageToBytes);
		return encode(encryptedBytes);
	}
	
	private String decrypt(String encryptedMessage) throws Exception{
		byte[] encryptedBytes = decode(encryptedMessage);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
		return new String(decryptedMessage,"UTF-8");
	}
	
	
	private String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
	
	private byte[] decode(String data) {
		return Base64.getDecoder().decode(data);
	}
	
	public void printKeys() {
		System.out.println("Public key: \n" + encode(publicKey.getEncoded()));
		System.out.println("Private key: \n " + encode(privateKey.getEncoded()));
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
