package com.metronet.yubikeymulator;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Calendar;
import java.util.Properties;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.yubico.base.Modhex;
import com.yubico.base.Token;
import com.yubico.base.tools.Hex;

/**
 * The Yubikeymulator is a Java-based Yubikey simulator. 
 * Using a simple properties file it can generate valid OTPs, 
 * simulating a real hardware Yubikey.
 * <p>
 * @author Yuval Ron (yuval@metro-net.co.il) 
 * <br> Any usage or copying is subject to the terms described under LICENSE file<br>
 * @version 1.0 
 * @see <a href="http://www.yubico.com/files/Security_Evaluation_2009-09-09.pdf">http://www.yubico.com/files/Security_Evaluation_2009-09-09.pdf</a> 
 */
public class Yubikeymulator implements IYubikey {
	
	public static final String PROP_COMMENT = 
		"All property values are stored in hex encoding ('52e1ff9a...') " +
		"except for publicId in Modhex";
	
	public static final String PUBLIC_ID = "publicId";
	public static final String PRIVATE_ID = "privateId";
	public static final String AES = "aes";
	public static final String SESSION_COUNTER = "sessionCtr";

	private static final int MAX_SESSION_COUNTER = 0xFFFF;
	private static final int MAX_SESSION_USE = 0xFF;

	private static final int BLOCK_SIZE = 16;
	private static final int RND_SIZE = 2;
	private static final int CRC_SIZE = 2;
	
	public static final int CRC_OK_RESIDUE = 0xf0b8;
	
	
	private Calendar _calendar = Calendar.getInstance();

	// simulating the yubikey volatile memory fields
	private byte _sessionUse; // simulating the session use
	private long _tsOffset; // simulating a random timestamp offset 	
	
	// simulating the yubikey's non-volatile memory by a properties file 
	private String _yubikeyPropFilename;
	private Properties _prop = new Properties(); 
	
	
	/**
	 * Constructs a Yubikey emulator by given properties file name
	 * @param yubikeyPropFilename
	 * @throws IOException
	 * @throws MaxSessionCounterExceededException
	 */
	public Yubikeymulator(String yubikeyPropFilename) 
			throws IOException, MaxSessionCounterExceededException {
		this._yubikeyPropFilename = yubikeyPropFilename;
		this.insert();
	}
	
	/**
	 * Initializes the Yubikey token by given Yubikey properties
	 * @param yubikeyPropFilename
	 * @throws IOException
	 * @throws MaxSessionCounterExceededException
	 */
	public void insert() 
			throws IOException, MaxSessionCounterExceededException  {
		
		FileInputStream fis = new FileInputStream(this._yubikeyPropFilename);
		this._prop.load(fis);
		fis.close();
		
		// generating a random offset for further timestamp calculations
		this._tsOffset = new Random(this._calendar.getTimeInMillis()).nextLong(); 
		// increasing the session counter
		this.increaseSessionCounter();
		// set session use to zero
		this._sessionUse = 0;
		
		FileOutputStream fos = new FileOutputStream(this._yubikeyPropFilename);
		this._prop.store(fos, PROP_COMMENT);
		fos.close();
	}
	

	/**
	 * Increases the session counter by 1, if not exceeding the maximum sessions allowed
	 * @return session counter
	 * @throws MaxSessionCounterExceededException
	 */
	private int increaseSessionCounter() throws MaxSessionCounterExceededException {
		// increase the session counter by 1 and save to non-volatile memory
		int sessionCtr = Integer.parseInt(this._prop.getProperty(SESSION_COUNTER), 16);
		sessionCtr ++;
		if (sessionCtr <= MAX_SESSION_COUNTER) {
			this._prop.setProperty(SESSION_COUNTER, Integer.toHexString(sessionCtr));
		}
		return sessionCtr;
	}
	
	
	/**
	 * Increases the session use field by 1. 
	 * If wrapping, set back to 0 and  
	 * @return the increase session use
	 * @throws MaxSessionCounterExceededException
	 */
	private void increaseSessionUse() throws MaxSessionCounterExceededException {		
		if (this._sessionUse < MAX_SESSION_USE) {
			this._sessionUse++;
		}
		else { // wrap and increase sessionCtr
			this.increaseSessionCounter();
		}		
	}
	
	
	/**
	 * Simulates a Yubikey click
	 * @return the generated encrypted otp
	 * @throws IOException
	 * @throws MaxSessionCounterExceededException
	 * @throws GeneralSecurityException
	 * @throws IllegalArgumentException
	 */
	public String click() throws IOException, MaxSessionCounterExceededException, 
		GeneralSecurityException, IllegalArgumentException {
		
		this.increaseSessionUse();
		byte[] decryptedBlock = this.generateOtpBlock();
		this.validateBlock(decryptedBlock); // if invalid throws IllegalArgumentException
		
		byte[] encryptedOtp = this.encryptBlock(decryptedBlock);	
		
		String publicId = this._prop.getProperty(PUBLIC_ID);
		
		String otp = publicId + Modhex.encode(encryptedOtp);
		
		return otp;
	}

	/** 
	 * Generates a dectypted otp block (byte[] sequence)
	 * @return the token
	 * @throws IOException
	 */
	private byte[] generateOtpBlock() throws IOException {		
		byte[] block = new byte[BLOCK_SIZE];
		
		long privateId = Long.parseLong(this._prop.getProperty(PRIVATE_ID), 16);
		block[0] = (byte)  (privateId & 0x0000000000ffL);
		block[1] = (byte) ((privateId & 0x00000000ff00L) >>  8);
		block[2] = (byte) ((privateId & 0x000000ff0000L) >> 16);
		block[3] = (byte) ((privateId & 0x0000ff000000L) >> 24);
		block[4] = (byte) ((privateId & 0x00ff00000000L) >> 32);
		block[5] = (byte) ((privateId & 0xff0000000000L) >> 40);
		
		int sessionCounter = Integer.parseInt(this._prop.getProperty(SESSION_COUNTER), 16);
		block[6] = (byte) (sessionCounter & 0x00ff);
		block[7] = (byte) (sessionCounter >> 8);

		long timestamp = this._calendar.getTimeInMillis() - this._tsOffset;
		block[8]  = (byte) (timestamp & 0x0000ff);
		block[9]  = (byte) ((timestamp & 0x00ff00) >> 8);
		block[10] = (byte) ((timestamp & 0xff0000) >> 16);

		block[11] = this._sessionUse;

		byte rnd[] = new byte[RND_SIZE];
		new Random(this._calendar.getTimeInMillis()).nextBytes(rnd);
		block[12] = rnd[1];
		block[13] = rnd[0];

		block[14] = 0;
		block[15] = 0;

		int crc = ~calcCrc( block, BLOCK_SIZE - CRC_SIZE );
		block[14] = (byte) (crc & 0x00ff);
		block[15] = (byte) (crc >> 8);

		return block; 
	}

	/**
	 * Encrypt a decrypted otp byte[] block by AES key and return the encrypted block
	 * @param decrypted block
	 * @return encrypted block
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	private byte[] encryptBlock(byte[] decrypted) 
			throws GeneralSecurityException, IOException {
		byte[] key = Hex.decode(this._prop.getProperty(AES));	
		
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
	    Cipher cipher = Cipher.getInstance("AES/ECB/Nopadding");
	    cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
	    
	    return cipher.doFinal(decrypted); // return the encrypted otp block
	}

	/**
	 * Calculate the crc code of the generated byte sequence
	 * @param b byte sequence
	 * @param length the array length (from 0) to calculate for
	 * @return the calculated crc code
	 * @throws IOException
	 */	
	private static int calcCrc(byte[] b, int length) {
		int crc = 0xffff;

		for (int i = 0; i < length; i++) {
			crc ^= b[i] & 0xFF;
			for (int j = 0; j < 8; j++){
				int n = crc & 1;
				crc >>= 1;
				if (n != 0) 
					crc ^= 0x8408;
			}
		}
		return crc;
	}

	/**
	 * Validates a generated decrypted otp block by creating a new {@link com.yubico.base.Token} 
	 * If invalid throws an IllegalArgumentException
	 * @param decryptedBlock
	 * @throws IllegalArgumentException
	 */
	private void validateBlock(byte[] decryptedBlock) 
			throws IllegalArgumentException {
		new Token(decryptedBlock);
	}

}
