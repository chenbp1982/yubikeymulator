package com.metronet.yubikeymulator;

/**
 * Thrown when the Yubikey session counter exceeds the max sessions allowed 
 * @author Yuval Ron <br> yuval@metro-net.co.il
 * @author Yuval
 * @version 1.0
 * @see <a href="http://www.yubico.com/files/Security_Evaluation_2009-09-09.pdf">http://www.yubico.com/files/Security_Evaluation_2009-09-09.pdf</a> 
*/
public class MaxSessionCounterExceededException extends Exception {
	public static final long serialVersionUID = 1L;
	
	
}
