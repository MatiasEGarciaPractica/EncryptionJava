package des;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * 
 * @author matia
 *	DES/CBC/NoPadding(56)
 *	DES/CBC/PKCS5Padding(56) *
 *	DES/ECB/NoPadding(56)
 *	DES/ECB/PKCS5Padding(56) * 
 *
 * Origin -> https://www.youtube.com/watch?v=XffVSIFRv3A&list=PLtgomJ95NvbPDMQClkBZPijLdEFyo0VHa&index=4
 * 
 * Encryption and Decryption with DES.
 *
 */
public class DesExample01 {

	private final SecretKey key;
	private Cipher encCipher;
	private Cipher decCipher;
	
	public static void main(String[] args) {
		String message = "The coders";
		try {
			DesExample01 des = new DesExample01();
			des.initCiphersCBC();
			//des.initCiphersECB();
			byte[] encryptedBytes = des.encrypt(message);
			String encodedMessage = encode(encryptedBytes);
			System.out.println("Encrypted message : " +	encodedMessage);
			byte[] decodedMessage = decode(encodedMessage);
			System.out.println("Decrypted message : " + des.decrypt(decodedMessage));
			des.show();
		}catch(Exception e) {
			e.printStackTrace();
		}
		
	}
	
	
	public DesExample01() throws Exception{
		this.key = generateKey();
	}
	
	public DesExample01(SecretKey key){
		this.key = key;
	}
	
	/**
	 * This needs encCipher IV.
	 * @throws Exception
	 */
	private void initCiphersCBC() throws Exception{
		encCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		decCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		encCipher.init(Cipher.ENCRYPT_MODE, key);
		decCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encCipher.getIV()));
	}
	
	/**
	 * this doesn't need the encCipher IV.
	 * @throws Exception
	 */
	private void initCiphersECB() throws Exception{
		encCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		decCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		encCipher.init(Cipher.ENCRYPT_MODE, key);
		decCipher.init(Cipher.DECRYPT_MODE, key);
	}
	
	public byte[] encrypt(String message) throws Exception{
		return encCipher.doFinal(message.getBytes());
	}
	
	public String decrypt(byte[] encryptedMessage) throws Exception {
		byte[] decryptedMessage = decCipher.doFinal(encryptedMessage);
		return new String(decryptedMessage);
	}
	
	
	public static SecretKey generateKey() throws Exception{
		return KeyGenerator.getInstance("DES").generateKey();
	}
	
	public static String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
	
	public static byte[] decode(String data) {
		return Base64.getDecoder().decode(data);
	}
	
	public  void show() {
		System.out.println("Des secretKey :" + encode(key.getEncoded()));
		System.out.println("IV : " + encode(encCipher.getIV()));
	}
	
}
