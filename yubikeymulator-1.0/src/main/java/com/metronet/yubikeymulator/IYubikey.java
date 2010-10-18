package com.metronet.yubikeymulator;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Interface for the Yubikeymulator, a Java-based Yubikey simulator. 
 * Using a simple properties file it can generate valid OTPs, 
 * simulating a real hardware Yubikey.
 * <p>
 * @author Yuval Ron (yuval@metro-net.co.il) 
 * <br> Any usage or copying is subject to the terms described under LICENSE file<br>
 * @version 1.0 
 * @see <a href="http://www.yubico.com/files/Security_Evaluation_2009-09-09.pdf">http://www.yubico.com/files/Security_Evaluation_2009-09-09.pdf</a> 
 */
public interface IYubikey {
	
	/**
	 * Initializes the Yubikey token by given Yubikey properties
	 * @param yubikeyPropFilename
	 * @throws IOException
	 * @throws MaxSessionCounterExceededException
	 */
	void insert() throws IOException, MaxSessionCounterExceededException;
	

	/**
	 * Simulates a Yubikey click
	 * @return the generated encrypted otp
	 * @throws IOException
	 * @throws MaxSessionCounterExceededException
	 * @throws GeneralSecurityException
	 * @throws IllegalArgumentException
	 */
	String click() throws IOException, MaxSessionCounterExceededException, 
		GeneralSecurityException, IllegalArgumentException;
	
}
