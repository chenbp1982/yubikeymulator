package com.metronet.yubikeymulator;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Unit test the Yubikeymulator functionality.
 * It is also recommended to perform tests via a real Yubikey validation server.  
 * <p>
 * @author Yuval Ron (yuval@metro-net.co.il) 
 * <br> Any usage or copying is subject to the terms described under LICENSE file<br>
 * @version 1.0 
 */
public class TestYubikeymulator {

	@Test
	public void testGenerateToken() {
		try {
			// perform a yubikey insert (increase sessionCtr)
			IYubikey yk = new Yubikeymulator("yubikey.properties");
			
			// perform a yubikey click 
			String otp1 = yk.click();
			assertNotNull(otp1);
			System.out.println(otp1);

			// perform a yubikey click 
			String otp2 = yk.click();
			assertNotNull(otp2);
			System.out.println(otp2);

			// perform another yubikey insert (increase sessionCtr)
			yk.insert();
			
			// perform a yubikey click 
			String otp3 = yk.click();
			assertNotNull(otp3);
			System.out.println(otp3);
		}
		catch (Exception ex) {
			ex.printStackTrace();
			fail();
		}
	}
	
}
