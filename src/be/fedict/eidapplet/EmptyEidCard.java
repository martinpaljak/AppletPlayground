/*
 * Quick-Key Toolset Project.
 * Copyright (C) 2010 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */
package be.fedict.eidapplet;

import javacard.framework.OwnerPIN;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;

public class EmptyEidCard extends EidCard {
	// these are identical for all eid card applet so share these between
	// subclasses
	static byte[] dirData, tokenInfoData, odfData, aodfData, prkdfData, cdfData;
	static byte[] citizenCaCert, rrnCert, rootCaCert;
	// save some more memory by making the photo static as well
	static byte[] photoData;
	/**
	 * called by the JCRE to create an applet instance
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// create a sample eID card applet instance
		new EmptyEidCard();
	}
	/**
	 * private constructor - called by the install method to instantiate a
	 * SampleEidCard instance
	 * 
	 * needs to be protected so that it can be invoked by subclasses
	 */
	protected EmptyEidCard() {
		super();
		// initialize PINs to fixed value
		initializePins();
		// initialize file system
		initializeFileSystem();
		// initialize place holders for large files (certificates + photo)
		initializeEmptyLargeFiles();
		// initialize basic keys pair
		initializeKeyPairs();
	}
	/**
	 * initialize all the PINs
	 * 
	 * PINs are set to the same values as the sample eID card
	 */
	private void initializePins() {
		/*
		 * initialize cardholder PIN (hardcoded to fixed value)
		 * 
		 * PIN header is "24" (length of PIN = 4) PIN itself is "1234" (4
		 * digits) fill rest of PIN data with F
		 */
		byte[] cardhold = { (byte) 0x24, (byte) 0x12, (byte) 0x34, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
		cardholderPin = new OwnerPIN(CARDHOLDER_PIN_TRY_LIMIT, PIN_SIZE);
		cardholderPin.update(cardhold, (short) 0, PIN_SIZE);
		/*
		 * initialize unblock PUK (hardcoded to fixed value)
		 * 
		 * PUK header is "2c" (length of PUK = 12) PUK itself consists of 2
		 * parts PUK2 is "222222" (6 digits) PUK1 is "111111" (6 digits) so in
		 * total the PUK is "222222111111" (12 digits) fill last bye of PUK data
		 * with "FF"
		 */
		byte[] unblock = { (byte) 0x2c, (byte) 0x22, (byte) 0x22, (byte) 0x22, (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0xFF };
		unblockPin = new OwnerPIN(UNBLOCK_PIN_TRY_LIMIT, PIN_SIZE);
		unblockPin.update(unblock, (short) 0, PIN_SIZE);
		/*
		 * activation PIN is same as PUK
		 */
		activationPin = new OwnerPIN(ACTIVATE_PIN_TRY_LIMIT, PIN_SIZE);
		activationPin.update(unblock, (short) 0, PIN_SIZE);
		/*
		 * initialize reset PIN (hardcoded to fixed value)
		 * 
		 * PUK header is "2c" (length of PUK = 12) PIN itself consists of 2
		 * parts PUK3 is "333333" (6 digits) PUK1 is "111111" (6 digits) so in
		 * total the PIN is "333333111111" (12 digits) fill last bye of PIN data
		 * with "FF"
		 */
		byte[] reset = { (byte) 0x2c, (byte) 0x33, (byte) 0x33, (byte) 0x33, (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0xFF };
		resetPin = new OwnerPIN(RESET_PIN_TRY_LIMIT, PIN_SIZE);
		resetPin.update(reset, (short) 0, PIN_SIZE);
	}
	/**
	 * Initialise all files on the card as empty with max size
	 * 
	 * see "Belgian Electronic Identity Card content" (version x)
	 * 
	 * depending on the eid card version, the address is of different length
	 * (current: 117)
	 */
	private void initializeFileSystem() {
		masterFile = new MasterFile();
		/*
		 * initialize PKCS#15 data structures see
		 * "5. PKCS#15 information details" for more info
		 */
		dirFile = new ElementaryFile(EF_DIR, masterFile, (short) 0x25);
		belpicDirectory = new DedicatedFile(DF_BELPIC, masterFile);
		tokenInfo = new ElementaryFile(TOKENINFO, belpicDirectory, (short) 0x30);
		objectDirectoryFile = new ElementaryFile(ODF, belpicDirectory, (short) 40);
		authenticationObjectDirectoryFile = new ElementaryFile(AODF, belpicDirectory, (short) 0x40);
		privateKeyDirectoryFile = new ElementaryFile(PRKDF, belpicDirectory, (short) 0xB0);
		certificateDirectoryFile = new ElementaryFile(CDF, belpicDirectory, (short) 0xB0);
		idDirectory = new DedicatedFile(DF_ID, masterFile);
		/*
		 * initialize all citizen data stored on the eID card copied from sample
		 * eID card 000-0000861-85
		 */
		// initialize ID#RN EF
		identityFile = new ElementaryFile(IDENTITY, idDirectory, (short) 0xD0);
		// initialize SGN#RN EF
		identityFileSignature = new ElementaryFile(SGN_IDENTITY, idDirectory, (short) 0x80);
		// initialize ID#Address EF
		// address is 117 bytes, and should be padded with zeros
		addressFile = new ElementaryFile(ADDRESS, idDirectory, (short) 117);
		// initialize SGN#Address EF
		addressFileSignature = new ElementaryFile(SGN_ADDRESS, idDirectory, (short) 128);
		// initialize PuK#7 ID (CA Role ID) EF
		caRoleIDFile = new ElementaryFile(CA_ROLE_ID, idDirectory, (short) 0x20);
		// initialize Preferences EF to 100 zero bytes
		preferencesFile = new ElementaryFile(PREFERENCES, idDirectory, (short) 100);
	}
	/**
	 * initialize empty files that need to be filled latter using UPDATE BINARY
	 */
	private void initializeEmptyLargeFiles() {
		/*
		 * these 3 certificates are the same for all sample eid card applets
		 * therefor they are made static and the data is allocated only once
		 */
		caCertificate = new ElementaryFile(CA_CERTIFICATE, belpicDirectory, (short) 1200);
		rrnCertificate = new ElementaryFile(RRN_CERTIFICATE, belpicDirectory, (short) 1200);
		rootCaCertificate = new ElementaryFile(ROOT_CA_CERTIFICATE, belpicDirectory, (short) 1200);
		/*
		 * to save some memory we only support 1 photo for all subclasses
		 * ideally this should be applet specific and have max size 3584 (3.5K)
		 */
		photoFile = new ElementaryFile(PHOTO, idDirectory, (short) 3584);
		/*
		 * certificate #2 and #3 are applet specific allocate enough memory
		 */
		authenticationCertificate = new ElementaryFile(AUTH_CERTIFICATE, belpicDirectory, (short) 1200);
		nonRepudiationCertificate = new ElementaryFile(NONREP_CERTIFICATE, belpicDirectory, (short) 1200);
	}
	/**
	 * initialize basic key pair
	 */
	private void initializeKeyPairs() {
		/*
		 * basicKeyPair is static (so same for all applets) so only allocate
		 * memory once
		 */
		if (EidCard.basicKeyPair != null)
			return;
		
		
		basicKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 1024);
		basicKeyPair.genKeyPair();
		
		authKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, (short) (1024));
		authKeyPair.genKeyPair();
		
		
	
		//authPrivateKey = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
		

		nonRepKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, (short) (1024));
		nonRepKeyPair.genKeyPair();
	
		//nonRepPrivateKey = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
	}
}
