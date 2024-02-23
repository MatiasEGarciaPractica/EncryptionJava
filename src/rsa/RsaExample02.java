package rsa;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

/**
 * 
 * @author matia
 * origin -> https://www.youtube.com/watch?v=jqGeUshOqeA&list=PLtgomJ95NvbPDMQClkBZPijLdEFyo0VHa&index=6
 * 
 * AES/CBC/NoPadding(128)
 * AES/CBC/PKCSSPaddig(128)
 * AES/ECB/NoPadding(128)
 * AES/ECB/PKCSSPadding(128)
 * RSA/ECB/PKCS1Padding(1024,2048)
 * RSA/ECB/OAEPWithSHA-1AndMGF1Padding(1024,2048)
 * RSA/ECB/OAEPWithSHA-256AndMGF1Padding(1024,2048)
 * 
 * we will import Public key and Private key from another app
 * 
 * origin -> https://www.youtube.com/watch?v=jqGeUshOqeA&list=PLtgomJ95NvbPDMQClkBZPijLdEFyo0VHa&index=6
 * 
 *  In the video is created a spring app, and in its controller has an endpoint where it returns a body encripted
 *  and from and another app , calls that endpoint, get the body encriptedn and decrypted it.
 * 
 */
public class RsaExample02 {


	private PrivateKey privateKey;
	private PublicKey publicKey;
	
	//here we have the public key and private key, in real application you will receive it 
	//from another app, in this case this are the private and public keys from RsaExample01.
	private static final String PUBLIC_KEY_STRING = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCL89ge3fFJ2yUayhFdi2JTnDLN25Zv1jHFTTV4hwK158EAQSGxKYhDsN1+LNs96WJWXk1LWBSNcS/2GX3+en7PEMm3opvc52ZX+Vvwg2J9T2nZlo9nYX3qLW93eWNVm1W1rKtMJ04tCiPdiH305RDSyZyw1Yy0JHp+Rge1B9hELQIDAQAB";
	private static final String PRIVATE_KEY_STRING = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIvz2B7d8UnbJRrKEV2LYlOcMs3blm/WMcVNNXiHArXnwQBBIbEpiEOw3X4s2z3pYlZeTUtYFI1xL/YZff56fs8Qybeim9znZlf5W/CDYn1PadmWj2dhfeotb3d5Y1WbVbWsq0wnTi0KI92IffTlENLJnLDVjLQken5GB7UH2EQtAgMBAAECgYAKyQNmOY9fNDKzUlAtR9EPhXGK2LnKq5SRUmZk/+6PCymd9eb9SqiUItym3RkWN9aatlC5ljObRNY/3m4Nvu3ntPauPlZnSZLG4iU+Tg1J6omd9+F+/vAy/kk85vkUED9+25eIU97NLzRZLI8DPsrUIhp7q8oZ/1oh06UMpBx6hwJBAMkj1CosqS67YdoLCh5bPKUpZT0M67dRsDI8yxo3/jgTIY4kWBDhOunMpnPNArU37IbsvmVQ1ByM6KD3S8C26pMCQQCyH7ttDCa4lqm9R2YDHp8UkXqilA1/YdUjW0PRJHIo6kZPBA4/X/4DKwV2QZgmQ3MTSb756gZUARcjgwCfzY4/AkAii7zM4Y7NL/HGeU7rl8/6rfltWuLBQY55kmdvwV4wU1jYCPX3MDfmH/gWu4dTiJ9fLRomXJORs8Hgo5inKMNxAkAVbvgQoRuvroFyQzslOPQPd4n4MjSFlXIeNQcuDWKnRbl8HJLSUWyxWOXpWu9B+2/HbGJMlDp6tT7hiQv0LrnlAkEAj3k+nDE0GDlVjGpAsX9+2FkrR/6WJZ4rbUHjWgad6ZaMzbQ2FA0UbjcheSZMD0RGMTTGjfuEqyWquO+OHyJWnA==";
	
	public static void main(String[] args) {
		RsaExample02 rsa = new RsaExample02();
		rsa.initFromStrings();
		try {
			String encryptedMessage = rsa.encrypt("Hello world");
			String decryptMessage = rsa.decrypt(encryptedMessage);
			
			System.err.println("Encrypted: \n" + encryptedMessage);
			System.err.println("Decrypted: \n" + decryptMessage);
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public void initFromStrings() {
		try {
			X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(PUBLIC_KEY_STRING));
			PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING));
			
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			
			publicKey = keyFactory.generatePublic(keySpecPublic);
			privateKey = keyFactory.generatePrivate(keySpecPrivate);
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
	
	
}
