/* 
 * Copyright (C) 2011  Digital Security group, Radboud University
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

package openemv;

import javacard.framework.ISOException;
import javacard.framework.Util;

/* Class to record all the static data of an EMV applet, ie. the card details that
 * do not change over time (such as PAN, expiry date, etc.), with the exception
 * of the cryptographic keys.
 * 
 * This static data is organised in the simplest possible way, using some public byte
 * arrays to record exact APDUs that the card has to produce.
 * 
 * This class does not offer personalisation support - everything is hard-coded.
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
 *
 */

public class EMVStaticData implements EMVConstants {

	private final byte[] theAFL = new byte[]{ (byte)0x08, 0x01, 0x03, 0x01}; // AFL from Dutch bank cards;

	/** Returns the 4 byte AFL (Application File Locator)  */
	public byte[] getAFL(){
	    return theAFL;
	}
	
	/** Returns the 2 byte AIP (Application Interchange Profile) 
	 *  See Book 3, Annex C1 for details
	 *   */
	public short getAIP() {
		return 0x5800;
		// 4000 SDA supported
		// 1000 Cardholder verification supported
		// 0800 Terminal risk management is to be performed
	}
	
	private final byte[] fci = new byte[]{
			0x6F, // FCI Template 
			0x25, // Length
			(byte)0x84, 0x07, (byte)0xA0, 0x00, 0x00, 0x00, 0x04, (byte)0x80, 0x02, // Dedicated File name 
			(byte)0xA5, 0x1A, // File Control Information Proprietary Template
				0x50, 0x0E, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x43, 0x6F, 0x64, 0x65, 0x20, 0x41, 0x75, 0x74, // Application Label  
				(byte)0x87, 0x01, 0x00, // Application Priority Indicator 
				0x5F, 0x2D, 0x04, 0x6E, 0x6C, 0x65, 0x6E // Language Preference
			};

	// File for EMV-CAP
	private final byte[] record1 = new byte[]{	
			0x70, // Read record message template
			0x00, // Record length
			(byte)0x8C, 0x21, (byte)0x9F, 0x02, 0x06, (byte)0x9F, 0x03, 0x06, (byte)0x9F, 0x1A, 0x02, (byte)0x95, 0x05, 0x5F, 0x2A, 0x02, (byte)0x9A, 0x03, (byte)0x9C, 0x01, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x35, 0x01, (byte)0x9F, 0x45, 0x02, (byte)0x9F, 0x4C, 0x08, (byte)0x9F, 0x34, 0x03, // Card Risk Management Data Object List 1 
			(byte)0x8D, 0x0C, (byte)0x91, 0x0A, (byte)0x8A, 0x02, (byte)0x95, 0x05, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x4C, 0x08, // Card Risk Management Data Object List 2
			0x5A, 0x05, 0x12, 0x34, 0x56, 0x78, (byte)0x90, // 5A Primary account number			
			0x5F, 0x34, 0x01, 0x02, // Bank identifier code
			(byte)0x8E, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // Cardholder Verification Method (CVM) List (Always transaction_data PIN performed by ICC) 
			(byte)0x9F, 0x55, 0x01, (byte)0x80, // Unknown field
			(byte)0x9F, 0x56, 0x0C, 0x00, 0x00, 0x7F, (byte)0xFF, (byte)0xFF, (byte)0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Bit filter
			};
 	
	/*
	// File for EMV
	private final byte[] record1 = new byte[]{
			0x70, // Read record message template
			0x00, // Record length
			// Mandatory data objects
			0x5F, 0x24, 0x03, // Application Expiry Date
			0x5A, 0x05, 0x12, 0x34, 0x56, 0x78, (byte)0x90, // 5A Primary account number
			(byte)0x8C, 0x21, (byte)0x9F, 0x02, 0x06, (byte)0x9F, 0x03, 0x06, (byte)0x9F, 0x1A, 0x02, (byte)0x95, 0x05, 0x5F, 0x2A, 0x02, (byte)0x9A, 0x03, (byte)0x9C, 0x01, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x35, 0x01, (byte)0x9F, 0x45, 0x02, (byte)0x9F, 0x4C, 0x08, (byte)0x9F, 0x34, 0x03, // Card Risk Management Data Object List 1
			(byte)0x8D, 0x18, (byte)0x91, 0x0A, (byte)0x8A, 0x02, (byte)0x95, 0x05, (byte)0x9F, 0x37, 0x04, (byte)0x9F, 0x4C, 0x08, // Card Risk Management Data Object List 2
			// Other data
			(byte)0x8E, 0x02, 0x01, 0x00, // Cardholder Verification Method (CVM) List (Always transaction_data PIN performed by ICC)
			(byte)0x9F, 0x4A, 0x01, (byte)0x82, // Static Data Authentication Tag List
			};
 	*/
	
	private final byte[] record2 = new byte[]{
			0x70, // Read record message template
			0x00, // Record length			
			// Data required for DDA/CDA
			(byte)0x8F, 0x00, // Certification Authority Public Key Index
			(byte)0x90, 0x00, // Issuer Public Key Certificate
			(byte)0x92, 0x00, // Issuer Public Key Remainder
			(byte)0x9F, 0x32, 0x00, // Issuer Public Key Exponent
			};
	
	private final byte[] record3 = new byte[]{
			0x70, // Read record message template
			0x00, // Record length			
			// Data required for DDA/CDA (continued)
			(byte)0x9F, 0x46, 0x00, // ICC Public Key Certificate
			(byte)0x9F, 0x47, 0x00, // ICC Public Key Exponent
			(byte)0x9F, 0x48, 0x00, // ICC Public Key Remainder
			(byte)0x9F, 0x49, 0x03, (byte)0x9F, 0x37, 0x04, // Dynamic Data Authentication Data Object List (DDOL)
			};
	
	/** Return the length of the data specified in the CDOL1 
	 * 
	 */
	public short getCDOL1DataLength() {
		return 0x2B;
		//return 43;
	}

	/** Return the length of the data specified in the CDOL2 
	 * 
	 */
	public short getCDOL2DataLength() {
		return 0x1D;
		//return 29;
	}
	
	public byte[] getFCI() {
		return fci;
	}

	public short getFCILength() {
		return (short)fci.length;
	}
	
	/** Provide the response to INS_READ_RECORD in the response buffer
	 * 
	 */
	public void readRecord(byte[] apduBuffer, byte[] response){
		if(apduBuffer[OFFSET_P2] == 0x0C && apduBuffer[OFFSET_P1] == 0x01) { // SFI 1, Record 1
			Util.arrayCopyNonAtomic(record1, (short)0, 
					response, (short)0, (short)record1.length);
			response[1] = (byte)(record1.length - 2); 
		}
		else if(apduBuffer[OFFSET_P2] == 0x0C && apduBuffer[OFFSET_P1] == 0x02) { // SFI 1, Record 2
			Util.arrayCopyNonAtomic(record2, (short)0, 
					response, (short)0, (short)record2.length);
			response[1] = (byte)(record2.length - 2); 
		}
		else if(apduBuffer[OFFSET_P2] == 0x0C && apduBuffer[OFFSET_P1] == 0x03) { // SFI 1, Record 3
			Util.arrayCopyNonAtomic(record3, (short)0, 
					response, (short)0, (short)record3.length);
			response[1] = (byte)(record3.length - 2); 
		}
		else {
			// File does not exist
			ISOException.throwIt(SW_FILE_NOT_FOUND);
		}
	}
	

}
