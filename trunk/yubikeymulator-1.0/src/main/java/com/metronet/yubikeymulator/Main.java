package com.metronet.yubikeymulator;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Yubikeymulator main(String[] args)
 * loads the Yubikeymulator with a provided properties filename param.
 * <p>
 * @author Yuval Ron (yuval@metro-net.co.il) 
 * <br> Any usage or copying is subject to the terms described under LICENSE file<br>
 * @version 1.0 
 */
public class Main {

	
	public static final String DEFAULT_YUBIKEY_PROPERTIES_FILENAME = "yubikey.properties";

	/**
	 * Launch Yubikeymulator app
	 * @param args the yubikey properties filename (optional)
	 * @param args
	 * @throws IOException
	 * @throws MaxSessionCounterExceededException
	 */
	public static void main(String[] args)
			throws IOException, MaxSessionCounterExceededException, 
			GeneralSecurityException {
		
		// use provided filename, otherwise use default
		String yubikeyPropFilename = 
			(args.length > 0) ? args[0] : 
			System.getProperty("user.dir") + System.getProperty("file.separator") + 
				DEFAULT_YUBIKEY_PROPERTIES_FILENAME;
		
		// create a new Yubikeymulator instance and simulate insert
		IYubikey yk = new Yubikeymulator(yubikeyPropFilename);
		
		// simulate click and print the next otp 
		System.out.println(yk.click());
		
		return;
	}
	
}
