
/*
 * Copyright (c) 2001
 * BSD ?
 */

//
// $Workfile: CardEdge.java $
// $Revision$
// $Date$
// $Author$
// $Archive: CardEdge $
// $Modtime: 5/02/00 8:48p $
//

package com.musclecard.CardEdge;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.DSAKey;
import javacard.security.DSAPrivateKey;
import javacard.security.DSAPublicKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

/**
 * Implements MUSCLE's Card Edge Specification.
 * <p>
 * 
 * TODO:
 * <ul>
 * <li>Allows maximum number of keys and PINs and total mem to be specified at
 * the instantiation moment.
 * <p>
 * <li>How do transactions fit in the methods ?
 * <li>Where should we issue begin/end transaction ?
 * <li>Should we ever abort transaction ? Where ?
 * <li>Every time there is an "if (avail < )" check, call ThrowDeleteObjects().
 * </ul>
 */

public class CardEdge extends javacard.framework.Applet implements ExtendedLength {

	/* constants declaration */

	// Maximum number of keys handled by the Cardlet
	private final static byte MAX_NUM_KEYS = (byte) 8;
	// Maximum number of PIN codes
	private final static byte MAX_NUM_PINS = (byte) 8;

	// Maximum number of keys allowed for ExtAuth
	private final static byte MAX_NUM_AUTH_KEYS = (byte) 6;

	// Maximum size for the extended APDU buffer for a 2048 bit key:
	// CLA [1 byte] + INS [1 byte] + P1 [1 byte] + P2 [1 byte] +
	// LC [3 bytes] + cipher_mode[1 byte] + cipher_direction [1 byte] +
	// data_location [1 byte] + data_size [2 bytes] + data [256 bytes]
	// = 268 bytes
	private final static short EXT_APDU_BUFFER_SIZE = (short) 268;

	// Minimum PIN size
	private final static byte PIN_MIN_SIZE = (byte) 4;
	// Maximum PIN size
	private final static byte PIN_MAX_SIZE = (byte) 16;

	// Maximum external authentication tries per key
	private final static byte MAX_KEY_TRIES = (byte) 5;

	// Import/Export Object ID
	private final static short IN_OBJECT_CLA = (short) 0xFFFF;
	private final static short IN_OBJECT_ID = (short) 0xFFFE;
	private final static short OUT_OBJECT_CLA = (short) 0xFFFF;
	private final static short OUT_OBJECT_ID = (short) 0xFFFF;

	private final static byte KEY_ACL_SIZE = (byte) 6;

	// Standard public ACL

	private static byte[] STD_PUBLIC_ACL;/*
										 * = { 0x0000, // Read always allowed
										 * 0x0000, // Write always allowed
										 * 0x0000 // Delete always allowed };
										 */

	private static byte[] acl; // Temporary ACL

	// code of CLA byte in the command APDU header
	private final static byte CardEdge_CLA = (byte) 0xB0;

	/****************************************
	 * Instruction codes *
	 ****************************************/

	// Applet initialization
	private final static byte INS_SETUP = (byte) 0x2A;

	// Keys' use and management
	private final static byte INS_GEN_KEYPAIR = (byte) 0x30;
	private final static byte INS_IMPORT_KEY = (byte) 0x32;
	private final static byte INS_EXPORT_KEY = (byte) 0x34;
	private final static byte INS_COMPUTE_CRYPT = (byte) 0x36;

	// External authentication
	private final static byte INS_CREATE_PIN = (byte) 0x40;
	private final static byte INS_VERIFY_PIN = (byte) 0x42;
	private final static byte INS_CHANGE_PIN = (byte) 0x44;
	private final static byte INS_UNBLOCK_PIN = (byte) 0x46;
	private final static byte INS_LOGOUT_ALL = (byte) 0x60;
	private final static byte INS_GET_CHALLENGE = (byte) 0x62;
	private final static byte INS_EXT_AUTH = (byte) 0x38;

	// Objects' use and management
	private final static byte INS_CREATE_OBJ = (byte) 0x5A;
	private final static byte INS_DELETE_OBJ = (byte) 0x52;
	private final static byte INS_READ_OBJ = (byte) 0x56;
	private final static byte INS_WRITE_OBJ = (byte) 0x54;

	// Status information
	private final static byte INS_LIST_OBJECTS = (byte) 0x58;
	private final static byte INS_LIST_PINS = (byte) 0x48;
	private final static byte INS_LIST_KEYS = (byte) 0x3A;
	private final static byte INS_GET_STATUS = (byte) 0x3C;


	/** There have been memory problems on the card */
	private final static short SW_NO_MEMORY_LEFT = ObjectManager.SW_NO_MEMORY_LEFT;
	/** Entered PIN is not correct */
	private final static short SW_AUTH_FAILED = (short) 0x9C02;
	/** Required operation is not allowed in actual circumstances */
	private final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
	/** Required feature is not (yet) supported */
	private final static short SW_UNSUPPORTED_FEATURE = (short) 0x9C05;
	/** Required operation was not authorized because of a lack of privileges */
	private final static short SW_UNAUTHORIZED = (short) 0x9C06;
	/** Required object is missing */
	private final static short SW_OBJECT_NOT_FOUND = (short) 0x9C07;
	/** New object ID already in use */
	private final static short SW_OBJECT_EXISTS = (short) 0x9C08;
	/** Algorithm specified is not correct */
	private final static short SW_INCORRECT_ALG = (short) 0x9C09;

	/** Incorrect P1 parameter */
	private final static short SW_INCORRECT_P1 = (short) 0x9C10;
	/** Incorrect P2 parameter */
	private final static short SW_INCORRECT_P2 = (short) 0x9C11;
	/** No more data available */
	private final static short SW_SEQUENCE_END = (short) 0x9C12;
	/** Invalid input parameter to command */
	private final static short SW_INVALID_PARAMETER = (short) 0x9C0F;

	/** Verify operation detected an invalid signature */
	private final static short SW_SIGNATURE_INVALID = (short) 0x9C0B;
	/** Operation has been blocked for security reason */
	private final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
	/** Unspecified error */
	private final static short SW_UNSPECIFIED_ERROR = (short) 0x9C0D;
	/** For debugging purposes */
	private final static short SW_INTERNAL_ERROR = (short) 0x9CFF;

	// Algorithm Type in APDUs
	private final static byte ALG_RSA = (byte) 0x00;
	private final static byte ALG_RSA_CRT = (byte) 0x01;
	private final static byte ALG_DSA = (byte) 0x02;
	private final static byte ALG_DES = (byte) 0x03;
	private final static byte ALG_3DES = (byte) 0x04;
	private final static byte ALG_3DES3 = (byte) 0x05;

	// Key Type in Key Blobs
	private final static byte KEY_RSA_PUBLIC = (byte) 0x01;
	private final static byte KEY_RSA_PRIVATE = (byte) 0x02;
	private final static byte KEY_RSA_PRIVATE_CRT = (byte) 0x03;
	private final static byte KEY_DSA_PUBLIC = (byte) 0x04;
	private final static byte KEY_DSA_PRIVATE = (byte) 0x05;
	private final static byte KEY_DES = (byte) 0x06;
	private final static byte KEY_3DES = (byte) 0x07;
	private final static byte KEY_3DES3 = (byte) 0x08;

	// KeyBlob Encoding in Key Blobs
	private final static byte BLOB_ENC_PLAIN = (byte) 0x00;

	// Cipher Operations admitted in ComputeCrypt()
	private final static byte OP_INIT = (byte) 0x01;
	private final static byte OP_PROCESS = (byte) 0x02;
	private final static byte OP_FINALIZE = (byte) 0x03;

	// Cipher Directions admitted in ComputeCrypt()
	private final static byte CD_SIGN = (byte) 0x01;
	private final static byte CD_VERIFY = (byte) 0x02;
	private final static byte CD_ENCRYPT = (byte) 0x03;
	private final static byte CD_DECRYPT = (byte) 0x04;

	// Cipher Modes admitted in ComputeCrypt()
	private final static byte CM_RSA_NOPAD = (byte) 0x00;
	private final static byte CM_RSA_PAD_PKCS1 = (byte) 0x01;
	private final static byte CM_DSA_SHA = (byte) 0x10;
	private final static byte CM_DES_CBC_NOPAD = (byte) 0x20;
	private final static byte CM_DES_ECB_NOPAD = (byte) 0x21;
	private final static byte DL_APDU = (byte) 0x01;
	private final static byte DL_OBJECT = (byte) 0x02;
	private final static byte LIST_OPT_RESET = (byte) 0x00;
	private final static byte LIST_OPT_NEXT = (byte) 0x01;

	private final static byte OPT_DEFAULT = (byte) 0x00; // Use JC defaults
	private final static byte OPT_RSA_PUB_EXP = (byte) 0x01; // RSA: provide public exponent
	private final static byte OPT_DSA_GPQ = (byte) 0x02; // DSA: provide p,q,g public key parameters 

	// Offsets in buffer[] for key generation
	private final static short OFFSET_GENKEY_ALG = (short) (ISO7816.OFFSET_CDATA);
	private final static short OFFSET_GENKEY_SIZE = (short) (ISO7816.OFFSET_CDATA + 1);
	private final static short OFFSET_GENKEY_PRV_ACL = (short) (ISO7816.OFFSET_CDATA + 3);
	private final static short OFFSET_GENKEY_PUB_ACL = (short) (OFFSET_GENKEY_PRV_ACL + KEY_ACL_SIZE);
	private final static short OFFSET_GENKEY_OPTIONS = (short) (OFFSET_GENKEY_PUB_ACL + KEY_ACL_SIZE);
	private final static short OFFSET_GENKEY_RSA_PUB_EXP_LENGTH = (short) (OFFSET_GENKEY_OPTIONS + 1);
	private final static short OFFSET_GENKEY_RSA_PUB_EXP_VALUE = (short) (OFFSET_GENKEY_RSA_PUB_EXP_LENGTH + 2);
	private final static short OFFSET_GENKEY_DSA_GPQ = (short) (OFFSET_GENKEY_OPTIONS + 1);

	/****************************************
	 * Instance variables declaration *
	 ****************************************/

	// Memory Manager
	private MemoryManager mem;
	// Object Manager
	private ObjectManager om;

	// Key objects (allocated on demand)
	private Key[] keys;
	// Key ACLs
	private byte[] keyACLs;
	// Key Tries Left
	private byte[] keyTries;
	// Key iterator for ListKeys: it's an offset in the keys[] array.
	private byte key_it;
	// True if a GetChallenge() has been issued
	private boolean getChallengeDone;

	/*
	 * KeyPair, Cipher and Signature objects * These are allocated on demand *
	 * TODO: Here we could have just 1 Object[] and * make proper casts when
	 * needed
	 */
	private Cipher[] ciphers;
	private Signature[] signatures;
	// Says if we are using a signature or a cipher object
	private byte[] ciph_dirs;
	private KeyPair[] keyPairs;
	private RandomData randomData; // RandomData class instance

	// PIN and PUK objects, allocated on demand
	private OwnerPIN[] pins, ublk_pins;

	// Buffer for storing extended APDUs
	private byte[] recvBuffer;

	/*
	 * Logged identities: this is used for faster access control, so we don't
	 * have to ping each PIN object
	 */
	private short logged_ids;

	/* For the setup function - should only be called once */
	private boolean setupDone = false;
	private byte create_object_ACL;
	private byte create_key_ACL;
	private byte create_pin_ACL;

	/****************************************
	 * Methods *
	 ****************************************/

	private CardEdge(byte[] bArray, short bOffset, byte bLength) {
	        ublk_pins = new OwnerPIN[MAX_NUM_PINS];
	        pins = new OwnerPIN[MAX_NUM_PINS];
		// FIXME: something should be done already here, not only with setup APDU
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		CardEdge wal = new CardEdge(bArray, bOffset, bLength);
		/* Register the Applet (copied code) */
		if (bArray[bOffset] == 0)
			wal.register();
		else
			wal.register(bArray, (short) (bOffset + 1), (byte) (bArray[bOffset]));
	}

	public boolean select() {
		/*
		 * Application has been selected: Do session cleanup operation
		 */

		// Destroy the IO objects (if they exist)
		if (setupDone) {
			om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
			om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
		}
		LogOutAll();
		return true;
	}

	public void deselect() {
		// Destroy the IO objects (if they exist)
		if (setupDone) {
			om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
			om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
		}
		LogOutAll();
	}

	public void process(APDU apdu) {
		// APDU object carries a byte array (buffer) to
		// transfer incoming and outgoing APDU header
		// and data bytes between card and CAD

		// At this point, only the first header bytes
		// [CLA, INS, P1, P2, P3] are available in
		// the APDU buffer.
		// The interface javacard.framework.ISO7816
		// declares constants to denote the offset of
		// these bytes in the APDU buffer

		if (selectingApplet())
			ISOException.throwIt(ISO7816.SW_NO_ERROR);

		byte[] buffer = apdu.getBuffer();
		// check SELECT APDU command
		if ((buffer[ISO7816.OFFSET_CLA] == 0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0xA4))
			return;
		// verify the rest of commands have the
		// correct CLA byte, which specifies the
		// command structure
		if (buffer[ISO7816.OFFSET_CLA] != CardEdge_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		byte ins = buffer[ISO7816.OFFSET_INS];
		if (!setupDone && (ins != (byte) INS_SETUP))
			ISOException.throwIt(SW_UNSUPPORTED_FEATURE);

		if (setupDone && (ins == (byte) INS_SETUP))
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

		switch (ins) {
		case INS_SETUP:
			setup(apdu, buffer);
			break;
		case INS_GEN_KEYPAIR:
			GenerateKeyPair(apdu, buffer);
			break;
		case INS_IMPORT_KEY:
			ImportKey(apdu, buffer);
			break;
		case INS_EXPORT_KEY:
			ExportKey(apdu, buffer);
			break;
		case INS_COMPUTE_CRYPT:
			ComputeCrypt(apdu, buffer);
			break;
		case INS_VERIFY_PIN:
			VerifyPIN(apdu, buffer);
			break;
		case INS_CREATE_PIN:
			CreatePIN(apdu, buffer);
			break;
		case INS_CHANGE_PIN:
			ChangePIN(apdu, buffer);
			break;
		case INS_UNBLOCK_PIN:
			UnblockPIN(apdu, buffer);
			break;
		case INS_LOGOUT_ALL:
			LogOutAll();
			break;
		case INS_GET_CHALLENGE:
			GetChallenge(apdu, buffer);
			break;
		case INS_EXT_AUTH:
			ExternalAuthenticate(apdu, buffer);
			break;
		case INS_CREATE_OBJ:
			CreateObject(apdu, buffer);
			break;
		case INS_DELETE_OBJ:
			DeleteObject(apdu, buffer);
			break;
		case INS_READ_OBJ:
			ReadObject(apdu, buffer);
			break;
		case INS_WRITE_OBJ:
			WriteObject(apdu, buffer);
			break;
		case INS_LIST_PINS:
			ListPINs(apdu, buffer);
			break;
		case INS_LIST_OBJECTS:
			ListObjects(apdu, buffer);
			break;
		case INS_LIST_KEYS:
			ListKeys(apdu, buffer);
			break;
		case INS_GET_STATUS:
			GetStatus(apdu, buffer);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		;
	} // end of process method


	/** Setup APDU - initialize the applet
	 * 
	 * Incoming data:
	 * PIN0 len + PIN0 + PUK0 len + PUK0 +
	 */
	private void setup(APDU apdu, byte[] buffer) {
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		short base = (short) (ISO7816.OFFSET_CDATA);

		byte numBytes = buffer[base++];

		OwnerPIN pin = pins[0];

		if (!CheckPINPolicy(buffer, base, numBytes))
		        ISOException.throwIt(SW_INVALID_PARAMETER);

		if (pin != null) {
		        if (pin.getTriesRemaining() == (byte) 0x00)
			        ISOException.throwIt(SW_IDENTITY_BLOCKED);

		        if (!pin.check(buffer, base, numBytes))
			        ISOException.throwIt(SW_AUTH_FAILED);
		}

		base += numBytes;

		byte pin_tries = buffer[base++];
		byte ublk_tries = buffer[base++];
		numBytes = buffer[base++];

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);

		pins[0] = new OwnerPIN(pin_tries, PIN_MAX_SIZE);
		pins[0].update(buffer, base, numBytes);

		base += numBytes;
		numBytes = buffer[base++];

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);

		ublk_pins[0] = new OwnerPIN(ublk_tries, PIN_MAX_SIZE);
		ublk_pins[0].update(buffer, base, numBytes);

		base += numBytes;

		pin_tries = buffer[base++];
		ublk_tries = buffer[base++];
		numBytes = buffer[base++];

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);

		pins[1] = new OwnerPIN(pin_tries, PIN_MAX_SIZE);
		pins[1].update(buffer, base, numBytes);

		base += numBytes;
		numBytes = buffer[base++];

		if (!CheckPINPolicy(buffer, base, numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);

		ublk_pins[1] = new OwnerPIN(ublk_tries, PIN_MAX_SIZE);
		ublk_pins[1].update(buffer, base, numBytes);
		base += numBytes;

		base += (short) 2;
		short mem_size = Util.getShort(buffer, base);
		base += (short) 2;

		create_object_ACL = buffer[base++];
		create_key_ACL = buffer[base++];
		create_pin_ACL = buffer[base++];

		mem = new MemoryManager((short) mem_size);
		om = new ObjectManager(mem);

		keys = new Key[MAX_NUM_KEYS];
		keyACLs = new byte[(short) (MAX_NUM_KEYS * KEY_ACL_SIZE)];
		keyTries = new byte[MAX_NUM_KEYS];
		for (byte i = (byte) 0; i < (byte) MAX_NUM_KEYS; i++)
			keyTries[i] = MAX_KEY_TRIES;
		keyPairs = new KeyPair[MAX_NUM_KEYS];
		ciphers = new Cipher[MAX_NUM_KEYS];
		signatures = new Signature[MAX_NUM_KEYS];
		ciph_dirs = new byte[MAX_NUM_KEYS];
		for (byte i = (byte) 0; i < (byte) MAX_NUM_KEYS; i++)
			ciph_dirs[i] = (byte) 0xFF;

		logged_ids = 0x00; // No identities logged in
		getChallengeDone = false; // No GetChallenge() issued so far
		randomData = null; // Will be created on demand when needed

		STD_PUBLIC_ACL = new byte[KEY_ACL_SIZE];
		for (byte i = (byte) 0; i < (byte) KEY_ACL_SIZE; i += (short) 2)
			Util.setShort(STD_PUBLIC_ACL, i, (short) 0x0000);

		// Initialize the extended APDU buffer
		try {
			// Try to allocate the extended APDU buffer on RAM memory
			recvBuffer = JCSystem.makeTransientByteArray((short) EXT_APDU_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
			// Allocate the extended APDU buffer on EEPROM memory
			// This is the fallback method, but its usage is really not
			// recommended
			// as after ~ 100000 writes it will kill the EEPROM cells...
			recvBuffer = new byte[EXT_APDU_BUFFER_SIZE];
		}

		setupDone = true;
	}

	/********** UTILITY FUNCTIONS **********/

	/*
	 * SendData() wraps the setOutgoing(), setLength(), .. stuff * that could be
	 * necessary to be fully JavaCard compliant.
	 */
	private void sendData(APDU apdu, byte[] data, short offset, short size) {
		if (size > EXT_APDU_BUFFER_SIZE)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		apdu.setOutgoing();
		apdu.setOutgoingLength(size);
		apdu.sendBytesLong(data, offset, size);
	}

	/* Retrieves the full contents from the apdu object in case of */
	/* an extended APDU. */
	private void getData(APDU apdu, byte[] src, short bytesRead, byte[] dst) {
		short recvLen = 0;
		short apduOffset = bytesRead;

		Util.arrayCopyNonAtomic(src, (short) 0, dst, (short) 0, apduOffset);
		do {
			recvLen = apdu.receiveBytes((short) 0);
			Util.arrayCopyNonAtomic(src, (short) 0, dst, apduOffset, recvLen);
			apduOffset += recvLen;
		} while (recvLen > 0);

	}

	/*
	 * Retrieves the Cipher object to be used w/ the specified key * and
	 * algorithm id (Cipher.ALG_XX). * If exists, check it has the proper
	 * algorithm and throws * SW_OP_NOT_ALLOWED if not * If not, creates it
	 */
	private Cipher getCipher(byte key_nb, byte alg_id) {
		if (ciphers[key_nb] == null) {
			ciphers[key_nb] = Cipher.getInstance(alg_id, false);
		} else if (ciphers[key_nb].getAlgorithm() != alg_id)
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		return ciphers[key_nb];
	}

	/*
	 * Retrieves the Signature object to be used w/ the specified key * and
	 * algorithm id (Signature.ALG_XX). * If exists, check it has the proper
	 * algorithm and throws * SW_OPERATION_NOT_ALLOWED if not * If does not
	 * exist, creates it
	 */
	private Signature getSignature(byte key_nb, byte alg_id) {
		if (signatures[key_nb] == null) {
			signatures[key_nb] = Signature.getInstance(alg_id, false);
		} else if (signatures[key_nb].getAlgorithm() != alg_id)
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		return signatures[key_nb];
	}

	/**
	 * Retrieves the Key object to be used w/ the specified key number, key type
	 * (KEY_XX) and size. If exists, check it has the proper key type If not,
	 * creates it.
	 * 
	 * @return Retrieved Key object or throws SW_UNATUTHORIZED,
	 *         SW_OPERATION_NOT_ALLOWED
	 */
	private Key getKey(byte key_nb, byte key_type, short key_size) {
		byte jc_key_type = keyType2JCType(key_type);

		if (keys[key_nb] == null) {
			// We have to create the Key

			/* Check that Identity n.0 is logged */
			if ((create_key_ACL == (byte) 0xFF)
					|| (((logged_ids & create_key_ACL) == (short) 0x0000) && (create_key_ACL != (byte) 0x00)))
				ISOException.throwIt(SW_UNAUTHORIZED);

			keys[key_nb] = KeyBuilder.buildKey(jc_key_type, key_size, false);
		} else {
			// Key already exists: check size & type
			/*
			 * TODO: As an option, we could just discard and recreate if not of
			 * the correct type, but creates trash objects
			 */
			if ((keys[key_nb].getSize() != key_size) || (keys[key_nb].getType() != jc_key_type))
				ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		}
		return keys[key_nb];
	}

	// Converts a Applet's Key Type to the JavaCard one.
	private byte keyType2JCType(byte key_type) {
		switch (key_type) {

		case KEY_RSA_PUBLIC:
			return KeyBuilder.TYPE_RSA_PUBLIC;
		case KEY_RSA_PRIVATE:
			return KeyBuilder.TYPE_RSA_PRIVATE;
		case KEY_RSA_PRIVATE_CRT:
			return KeyBuilder.TYPE_RSA_CRT_PRIVATE;
		case KEY_DSA_PUBLIC:
			return KeyBuilder.TYPE_DSA_PUBLIC;
		case KEY_DSA_PRIVATE:
			return KeyBuilder.TYPE_DSA_PUBLIC;
		case KEY_DES:
			return KeyBuilder.TYPE_DES;
		case KEY_3DES:
		case KEY_3DES3:
			return KeyBuilder.TYPE_DES;
		default:
			ISOException.throwIt(SW_INVALID_PARAMETER);
		}
		return (byte) 0; // Avoid compiler warning
	}

	// Converts a JavaCard's Key Type to the Applet one.
	private byte getKeyType(Key key) {
		switch (key.getType()) {

		case KeyBuilder.TYPE_RSA_PUBLIC:
			return KEY_RSA_PUBLIC;
		case KeyBuilder.TYPE_RSA_PRIVATE:
			return KEY_RSA_PRIVATE;
		case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
			return KEY_RSA_PRIVATE_CRT;
		case KeyBuilder.TYPE_DSA_PUBLIC:
			return KEY_DSA_PUBLIC;
		case KeyBuilder.TYPE_DSA_PRIVATE:
			return KEY_DSA_PRIVATE;
		case KeyBuilder.TYPE_DES:
			if (key.getSize() == (short) 64)
				return KEY_DES;
			if (key.getSize() == (short) 128)
				return KEY_3DES;
			if (key.getSize() == (short) 192)
				return KEY_3DES3;
		default:
			ISOException.throwIt(SW_INTERNAL_ERROR);
		}
		return (byte) 0; // Avoid compiler warning
	}

	/** Check from ACL if a key can be read */
	boolean authorizeKeyRead(byte key_nb) {
		short acl_offset = (short) (key_nb * KEY_ACL_SIZE);
		short required_ids = Util.getShort(keyACLs, acl_offset);
		return ((required_ids != (short) 0xFFFF) && ((short) (required_ids & logged_ids) == required_ids));
	}

	/** Check from ACL if a key can be overwritten */
	boolean authorizeKeyWrite(byte key_nb) {
		short acl_offset = (short) (key_nb * KEY_ACL_SIZE + 2);
		short required_ids = Util.getShort(keyACLs, acl_offset);
		return ((required_ids != (short) 0xFFFF) && ((short) (required_ids & logged_ids) == required_ids));
	}

	/** Check from ACL if a key can be used */
	boolean authorizeKeyUse(byte key_nb) {
		short acl_offset = (short) (key_nb * KEY_ACL_SIZE + 4);
		short required_ids = Util.getShort(keyACLs, acl_offset);
		return ((required_ids != (short) 0xFFFF) && ((short) (required_ids & logged_ids) == required_ids));
	}

	/** Returns an ACL that requires current logged in identities. */
	byte[] getCurrentACL() {
		if (acl == null)
			acl = new byte[KEY_ACL_SIZE];
		byte i;
		for (i = (byte) 0; i < KEY_ACL_SIZE; i += (byte) 2)
			Util.setShort(acl, i, logged_ids);
		return acl;
	}

	/** Returns an ACL that disables all operations for the application. */
	byte[] getRestrictedACL() {
		if (acl == null)
			acl = new byte[KEY_ACL_SIZE];
		byte i;
		for (i = (byte) 0; i < KEY_ACL_SIZE; i += (byte) 2)
			Util.setShort(acl, i, (short) 0xFFFF);
		return acl;
	}

	/** Registers login of strong identity associated with a key number */
	private void LoginStrongIdentity(byte key_nb) {
		logged_ids |= (short) (((short) 0x01) << (key_nb + 8));
	}

	/**
	 * Registers logout of an identity. This must be called anycase when a PIN
	 * verification or external authentication fail
	 */
	private void LogoutIdentity(byte id_nb) {
		logged_ids &= (short) ~(0x0001 << id_nb);
	}

	/** Deletes and zeros the IO objects and throws the passed in exception */
	private void ThrowDeleteObjects(short exception) {
		om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
		om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
		ISOException.throwIt(exception);
	}

	/** Checks if PIN policies are satisfied for a PIN code */
	private boolean CheckPINPolicy(byte[] pin_buffer, short pin_offset, byte pin_size) {
		if ((pin_size < PIN_MIN_SIZE) || (pin_size > PIN_MAX_SIZE))
			return false;
		return true;
	}

	/****************************************
	 * APDU handlers *
	 ****************************************/

	private void ComputeCrypt(APDU apdu, byte[] apduBuffer) {
		/* Buffer pointer */
		byte[] buffer = apduBuffer;

		short bytesLeft = apdu.setIncomingAndReceive();
		short LC = apdu.getIncomingLength();
		short dataOffset = apdu.getOffsetCdata();

		if ((short) (LC + dataOffset) > EXT_APDU_BUFFER_SIZE)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		/* Is this an extended APDU? */
		if (bytesLeft != LC) {
			getData(apdu, apduBuffer, (short) (dataOffset + bytesLeft), recvBuffer);
			buffer = recvBuffer;
			bytesLeft = LC;
		}
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS) || (keys[key_nb] == null))
			ISOException.throwIt(SW_INCORRECT_P1);
		/* Enforce Access Control */
		if (!authorizeKeyUse(key_nb))
			ISOException.throwIt(SW_UNAUTHORIZED);
		byte op = buffer[ISO7816.OFFSET_P2];
		Key key = keys[key_nb];
		byte ciph_dir;
		byte data_location;
		byte[] src_buff;
		short src_base;
		short src_avail;
		short size;
		switch (op) {
		case OP_INIT:
			if (bytesLeft < 3)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			byte ciph_mode = buffer[dataOffset];
			ciph_dir = buffer[(short) (dataOffset + 1)];
			byte ciph_alg_id;
			data_location = buffer[(short) (dataOffset + 2)];
			switch (data_location) {
			case DL_APDU:
				src_buff = buffer;
				src_base = (short) (dataOffset + 3);
				src_avail = (short) (bytesLeft - 3);
				break;
			case DL_OBJECT:
				src_buff = mem.getBuffer();
				src_base = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
				if (src_base == MemoryManager.NULL_OFFSET)
					ISOException.throwIt(SW_OBJECT_NOT_FOUND);
				src_avail = om.getSizeFromAddress(src_base);
				break;
			default:
				ISOException.throwIt(SW_INVALID_PARAMETER);
				return; // Compiler warning
			}
			if (src_avail < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			size = Util.getShort(src_buff, src_base);
			if (src_avail < (short) (2 + size))
				ISOException.throwIt(SW_INVALID_PARAMETER);
			switch (ciph_dir) {
			case CD_SIGN:
			case CD_VERIFY:
				switch (key.getType()) {
				case KeyBuilder.TYPE_RSA_PUBLIC:
				case KeyBuilder.TYPE_RSA_PRIVATE:
					ciph_alg_id = Signature.ALG_RSA_MD5_PKCS1;
					ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
					break;
				case KeyBuilder.TYPE_DSA_PUBLIC:
				case KeyBuilder.TYPE_DSA_PRIVATE:
					if (ciph_mode == CM_DSA_SHA)
						ciph_alg_id = Signature.ALG_DSA_SHA;
					else {
						ISOException.throwIt(SW_INVALID_PARAMETER);
						return; // Compiler warning (ciph_alg_id)
					}
					break;
				default:
					// DSA Encryption/Decryption is not supported by JavaCard !!
					ISOException.throwIt(SW_INCORRECT_ALG);
					return; // Compiler warning (ciph_alg_id)
				}
				Signature sign = getSignature(key_nb, ciph_alg_id);
				if (size == (short) 0)
					sign.init(key, (ciph_dir == CD_SIGN) ? Signature.MODE_SIGN : Signature.MODE_VERIFY);
				else
					sign.init(key, (ciph_dir == CD_SIGN) ? Signature.MODE_SIGN : Signature.MODE_VERIFY, src_buff,
							(short) (src_base + 2), size);
				ciph_dirs[key_nb] = ciph_dir;
				break;
			case CD_ENCRYPT:
			case CD_DECRYPT:
				switch (key.getType()) {
				case KeyBuilder.TYPE_RSA_PUBLIC:
				case KeyBuilder.TYPE_RSA_PRIVATE:
				case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
					if (ciph_mode == CM_RSA_NOPAD)
						ciph_alg_id = Cipher.ALG_RSA_NOPAD;
					else if (ciph_mode == CM_RSA_PAD_PKCS1)
						ciph_alg_id = Cipher.ALG_RSA_PKCS1;
					else {
						ISOException.throwIt(SW_INVALID_PARAMETER);
						return;
					}
					break;
				case KeyBuilder.TYPE_DES:
					if (ciph_mode == CM_DES_CBC_NOPAD)
						ciph_alg_id = Cipher.ALG_DES_CBC_NOPAD;
					else if (ciph_mode == CM_DES_ECB_NOPAD)
						ciph_alg_id = Cipher.ALG_DES_ECB_NOPAD;
					else {
						ISOException.throwIt(SW_INVALID_PARAMETER);
						return;
					}
					break;
				case KeyBuilder.TYPE_DSA_PUBLIC:
				case KeyBuilder.TYPE_DSA_PRIVATE:
					// DSA Encryption/Decryption is not supported by JavaCard !!
					ISOException.throwIt(SW_INVALID_PARAMETER);
					return;
				default:
					ISOException.throwIt(SW_INTERNAL_ERROR);
					return; // Compiler warning (ciph_alg_id unset)
				}
				Cipher ciph = getCipher(key_nb, ciph_alg_id);
				if (size == (short) 0)
					ciph.init(key, (ciph_dir == CD_ENCRYPT) ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT);
				else
					ciph.init(key, (ciph_dir == CD_ENCRYPT) ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT, src_buff,
							(short) (src_base + 2), size);
				ciph_dirs[key_nb] = ciph_dir;
				break;
			default:
				ISOException.throwIt(SW_INVALID_PARAMETER);
			}
			break;
		case OP_PROCESS:
		case OP_FINALIZE:
			ciph_dir = ciph_dirs[key_nb];
			switch (ciph_dir) {
			case CD_SIGN:
			case CD_VERIFY:
				Signature sign = signatures[key_nb];
				if (sign == null)
					/*
					 * Don't know what is incorrect: just say incorrect
					 * parameters we guess it was specified a wrong key number
					 */
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				data_location = buffer[dataOffset];
				switch (data_location) {
				case DL_APDU:
					src_buff = mem.getBuffer();
					// Skip Data Location byte.
					src_base = (short) (dataOffset + 1);
					src_avail = (short) (bytesLeft - 1);
					break;
				case DL_OBJECT:
					src_buff = mem.getBuffer();
					src_base = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
					if (src_base == MemoryManager.NULL_OFFSET)
						ISOException.throwIt(SW_OBJECT_NOT_FOUND);
					src_avail = om.getSizeFromAddress(src_base);
					break;
				default:
					ISOException.throwIt(SW_INVALID_PARAMETER);
					return;
				}
				if (src_avail < 2)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				size = Util.getShort(src_buff, src_base);
				// IO objects are allowed to be larger than size of contained
				// data
				if (src_avail < (short) (2 + size))
					ISOException.throwIt(SW_INVALID_PARAMETER);
				if (op == OP_PROCESS)
					sign.update(src_buff, (short) (src_base + 2), size);
				else {
					// OP_FINALIZE
					if (ciph_dir == CD_SIGN) {
						om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
						short dst_base = om.createObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, (short) (sign.getLength() + 2),
								getCurrentACL(), (short) 0);
						if (dst_base == MemoryManager.NULL_OFFSET)
							ISOException.throwIt(SW_NO_MEMORY_LEFT);
						short sign_size = sign.sign(src_buff, (short) (src_base + 2), size, mem.getBuffer(),
								(short) (dst_base + 2));
						if (sign_size > sign.getLength())
							// We got a buffer overflow (unless we were in
							// memory end and got an exception...)
							ISOException.throwIt(SW_INTERNAL_ERROR);
						mem.setShort(dst_base, sign_size);
						// Actually send data back (and clear output buffer)
						// only if location is APDU
						if (data_location == DL_APDU) {
							sendData(apdu, mem.getBuffer(), dst_base, (short) (sign_size + 2));
							om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
						}
					} else { // ciph_dir == CD_VERIFY
						if (src_avail < (short) (2 + size + 2))
							ISOException.throwIt(SW_INVALID_PARAMETER);
						short sign_size = Util.getShort(src_buff, (short) (src_base + 2 + size));
						if (src_avail < (short) (2 + size + 2 + sign_size))
							ISOException.throwIt(SW_INVALID_PARAMETER);
						if (sign_size != sign.getLength())
							ISOException.throwIt(SW_INVALID_PARAMETER);
						if (!sign.verify(src_buff, (short) (src_base + 2), size, src_buff,
								(short) (src_base + 2 + size + 2), sign_size))
							ISOException.throwIt(SW_SIGNATURE_INVALID);
					}
				}
				break;
			case CD_ENCRYPT:
			case CD_DECRYPT:
				Cipher ciph = ciphers[key_nb];
				if (ciph == null)
					/*
					 * Don't know what is incorrect: just say incorrect
					 * parameters we guess it was specified a wrong key number
					 */
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				data_location = buffer[dataOffset];
				switch (data_location) {
				case DL_APDU:
					src_buff = buffer;
					src_base = (short) (dataOffset + 1);
					src_avail = (short) (bytesLeft - 1);
					break;
				case DL_OBJECT:
					src_buff = mem.getBuffer();
					src_base = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
					if (src_base == MemoryManager.NULL_OFFSET)
						ISOException.throwIt(SW_OBJECT_NOT_FOUND);
					src_avail = om.getSizeFromAddress(src_base);
					break;
				default:
					ISOException.throwIt(SW_INVALID_PARAMETER);
					return;
				}
				if (src_avail < 2)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				size = Util.getShort(src_buff, src_base);
				if (src_avail < (short) (2 + size))
					ISOException.throwIt(SW_INVALID_PARAMETER);
				// TODO: Don't destroy the out obj every time, but keep it
				om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
				// Create object with 2 more bytes for DataChunk Size field
				short dst_base = om.createObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, (short) (size + 2), getCurrentACL(),
						(short) 0);
				if (dst_base == MemoryManager.NULL_OFFSET)
					ISOException.throwIt(SW_NO_MEMORY_LEFT);
				mem.setShort(dst_base, size);
				if (op == OP_PROCESS)
					ciph.update(src_buff, (short) (src_base + 2), size, mem.getBuffer(), (short) (dst_base + 2));
				else
					/* op == OP_FINAL */
					ciph.doFinal(src_buff, (short) (src_base + 2), size, mem.getBuffer(), (short) (dst_base + 2));
				if (data_location == DL_APDU) {
					// Also copies the Short size information
					Util.arrayCopyNonAtomic(mem.getBuffer(), dst_base, buffer, (short) 0, (short) (size + 2));
					om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
					sendData(apdu, buffer, (short) 0, (short) (size + 2));
				}
				break;
			default:
				// Internal error because it should have been checked on INIT
				ISOException.throwIt(SW_INTERNAL_ERROR);
			}
			break;
		default:
			ISOException.throwIt(SW_INCORRECT_P2);
		}
	}

	private void GenerateKeyPair(APDU apdu, byte[] buffer) {
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		byte alg_id = buffer[OFFSET_GENKEY_ALG];
		switch (alg_id) {
		case ALG_RSA:
		case ALG_RSA_CRT:
			GenerateKeyPairRSA(buffer);
			break;
		case ALG_DSA:
			GenerateKeyPairDSA(buffer);
			break;
		default:
			ISOException.throwIt(SW_INCORRECT_ALG);
		}
	}

	// Data has already been receive()ed
	private void GenerateKeyPairRSA(byte[] buffer) {
		byte prv_key_nb = buffer[ISO7816.OFFSET_P1];
		if ((prv_key_nb < 0) || (prv_key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		byte pub_key_nb = buffer[ISO7816.OFFSET_P2];
		if ((pub_key_nb < 0) || (pub_key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P2);
		if (pub_key_nb == prv_key_nb)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		byte alg_id = buffer[OFFSET_GENKEY_ALG];
		short key_size = Util.getShort(buffer, OFFSET_GENKEY_SIZE);
		byte options = buffer[OFFSET_GENKEY_OPTIONS];
		RSAPublicKey pub_key = (RSAPublicKey) getKey(pub_key_nb, KEY_RSA_PUBLIC, key_size);
		PrivateKey prv_key = (PrivateKey) getKey(prv_key_nb, alg_id == ALG_RSA ? KEY_RSA_PRIVATE : KEY_RSA_PRIVATE_CRT,
				key_size);
		/* If we're going to overwrite a keyPair's contents, check ACL */
		if (pub_key.isInitialized() && !authorizeKeyWrite(pub_key_nb))
			ISOException.throwIt(SW_UNAUTHORIZED);
		if (prv_key.isInitialized() && !authorizeKeyWrite(prv_key_nb))
			ISOException.throwIt(SW_UNAUTHORIZED);
		/* Store private key ACL */
		Util.arrayCopy(buffer, OFFSET_GENKEY_PRV_ACL, keyACLs, (short) (prv_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
		/* Store public key ACL */
		Util.arrayCopy(buffer, OFFSET_GENKEY_PUB_ACL, keyACLs, (short) (pub_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
		switch (options) {
		case OPT_DEFAULT:
			/*
			 * As the default was specified, if public key already * exist we
			 * have to invalidate it, otherwise its parameters * would be used
			 * in place of the default ones
			 */
			if (pub_key.isInitialized())
				pub_key.clearKey();
			break;
		case OPT_RSA_PUB_EXP:
			short exp_length = Util.getShort(buffer, OFFSET_GENKEY_RSA_PUB_EXP_LENGTH);
			pub_key.setExponent(buffer, OFFSET_GENKEY_RSA_PUB_EXP_VALUE, exp_length);
			break;
		default:
			ISOException.throwIt(SW_INVALID_PARAMETER);
		}
		/*
		 * TODO: Migrate checks on KeyPair on the top, so we avoid resource
		 * allocation on error conditions
		 */
		/*
		 * If no keypair was previously used, ok. If different keypairs were
		 * used, or for 1 key there is a keypair but the other key not, then
		 * error If the same keypair object was used previously, check keypair
		 * size & type
		 */
		if ((keyPairs[pub_key_nb] == null) && (keyPairs[prv_key_nb] == null)) {
			keyPairs[pub_key_nb] = new KeyPair(pub_key, prv_key);
			keyPairs[prv_key_nb] = keyPairs[pub_key_nb];
		} else if (keyPairs[pub_key_nb] != keyPairs[prv_key_nb])
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		KeyPair kp = keyPairs[pub_key_nb];
		if ((kp.getPublic() != pub_key) || (kp.getPrivate() != prv_key))
			// This should never happen according with this Applet policies
			ISOException.throwIt(SW_INTERNAL_ERROR);
		// We Rely on genKeyPair() to make all necessary checks about types
		kp.genKeyPair();
	}

	// Data has already been receive()ed
	private void GenerateKeyPairDSA(byte[] buffer) {
		byte prv_key_nb = buffer[ISO7816.OFFSET_P1];
		if ((prv_key_nb < 0) || (prv_key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		byte pub_key_nb = buffer[ISO7816.OFFSET_P2];
		if ((pub_key_nb < 0) || (pub_key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P2);
		short key_size = Util.getShort(buffer, OFFSET_GENKEY_SIZE);
		byte options = buffer[OFFSET_GENKEY_OPTIONS];
		if (pub_key_nb == prv_key_nb)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		DSAPublicKey pub_key = (DSAPublicKey) getKey(pub_key_nb, KEY_DSA_PUBLIC, key_size);
		DSAPrivateKey prv_key = (DSAPrivateKey) getKey(prv_key_nb, KEY_DSA_PRIVATE, key_size);
		/* If we're going to overwrite a keyPair's contents, check ACL */
		if (pub_key.isInitialized() && !authorizeKeyWrite(pub_key_nb))
			ISOException.throwIt(SW_UNAUTHORIZED);
		if (prv_key.isInitialized() && !authorizeKeyWrite(prv_key_nb))
			ISOException.throwIt(SW_UNAUTHORIZED);
		/* Store private key ACL */
		Util.arrayCopy(buffer, OFFSET_GENKEY_PRV_ACL, keyACLs, (short) (prv_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
		/* Store public key ACL */
		Util.arrayCopy(buffer, OFFSET_GENKEY_PUB_ACL, keyACLs, (short) (pub_key_nb * KEY_ACL_SIZE), KEY_ACL_SIZE);
		switch (options) {
		case OPT_DEFAULT:
			// As default params were specified, we have to clear the
			// public key if already initialized, otherwise their params
			// would be used.
			if (pub_key.isInitialized())
				pub_key.clearKey();
			break;
		case OPT_DSA_GPQ:
			short base = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
			if (base == MemoryManager.NULL_OFFSET)
				ISOException.throwIt(SW_OBJECT_NOT_FOUND);
			short avail = om.getSizeFromAddress(base);
			if (avail < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			DSAGetGPQ(mem.getBuffer(), base, avail, pub_key);
			om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
			break;
		default:
			ISOException.throwIt(SW_INVALID_PARAMETER);
		}
		/*
		 * TODO: Migrate checks on KeyPair on the top, so we avoid resource
		 * allocation on error conditions
		 */
		/*
		 * If no keypair was previously used, ok. If different keypairs were
		 * used, or for 1 key there is a keypair but the other key not, then
		 * error If the same keypair object was used previously, check keypair
		 * size & type
		 */
		if ((keyPairs[pub_key_nb] == null) && (keyPairs[prv_key_nb] == null)) {
			keyPairs[pub_key_nb] = new KeyPair(pub_key, prv_key);
			keyPairs[prv_key_nb] = keyPairs[pub_key_nb];
		} else if (keyPairs[pub_key_nb] != keyPairs[prv_key_nb])
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		KeyPair kp = keyPairs[pub_key_nb];
		if ((kp.getPublic() != pub_key) || (kp.getPrivate() != prv_key))
			// This should never happen with this Applet policies
			ISOException.throwIt(SW_INTERNAL_ERROR);
		// We Rely on genKeyPair() to make all necessary checks about types
		try {
			kp.genKeyPair();
		} catch (Exception e) {
			ISOException.throwIt(SW_UNSPECIFIED_ERROR);
		}
	}

	/**
	 * Reads parameters G, P, Q from a buffer and sets them in a DSA key.
	 * 
	 * @param buffer
	 *            The buffer
	 * @param base
	 *            The offset in buffer[] where parameters start
	 * @param avail
	 *            The maximum number of bytes allowed to read in buffer[]. If it
	 *            was not possible to read parameters within avail bytes
	 *            starting from base, throw a DATA_INVALID exception.
	 * @param key
	 *            The destination DSAKey object.
	 * @return The effective number of bytes read
	 */
	private short DSAGetGPQ(byte[] buffer, short base, short avail, DSAKey key) {
		short size;
		short orig_base = base;
		if (avail < 2)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		size = Util.getShort(buffer, base);
		base += (short) 2; // Skip G Size
		avail -= (short) 2;
		if (avail < (short) (size + 2))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		key.setG(buffer, base, size);
		base += size; // Skip G Value
		avail -= size;
		// avail ok...
		size = Util.getShort(buffer, base);
		base += (short) 2; // Skip P Size
		avail -= (short) 2;
		if (avail < (short) (size + 2))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		key.setP(buffer, base, size);
		base += size; // Skip P Value
		avail -= size;
		// avail ok...
		size = Util.getShort(buffer, base);
		base += (short) 2; // Skip Q Size
		avail -= (short) 2;
		if (avail < size)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		key.setQ(buffer, base, size);
		base += size; // Skip Q Value
		avail -= size;
		return (short) (base - orig_base);
	}

	private void ImportKey(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		/* If we're going to overwrite a key contents, check ACL */
		if ((keys[key_nb] != null) && keys[key_nb].isInitialized() && !authorizeKeyWrite(key_nb))
			ISOException.throwIt(SW_UNAUTHORIZED);
		// Get memory base offset of the input buffer
		short base = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
		if (base == MemoryManager.NULL_OFFSET)
			ISOException.throwIt(SW_OBJECT_NOT_FOUND);
		short avail = om.getSizeFromAddress(base);
		/*** Start reading key blob ***/
		// Check entire blob header
		if (avail < 4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Check Blob Encoding
		if (mem.getByte(base) != BLOB_ENC_PLAIN)
			// TODO: Encrypted key blob ?
			ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
		base++; // Skip Blob Encoding
		avail--;
		byte key_type = mem.getByte(base);
		base++; // Skip Key Type
		avail--;
		short key_size = mem.getShort(base);
		base += (short) 2; // Skip Key Size
		avail -= (short) 2;
		short size;
		switch (key_type) {
		case KEY_RSA_PUBLIC:
			RSAPublicKey rsa_pub_key = (RSAPublicKey) getKey(key_nb, key_type, key_size);
			if (avail < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			size = mem.getShort(base);
			base += (short) 2; // Skip Mod Size
			avail -= (short) 2;
			if (avail < (short) (size + 2))
				ISOException.throwIt(SW_INVALID_PARAMETER);
			rsa_pub_key.setModulus(mem.getBuffer(), base, size);
			base += size; // Skip Mod Value
			avail -= size;
			// avail already checked in previous if ()
			size = mem.getShort(base);
			base += (short) 2; // Skip Exp Size
			avail -= (short) 2;
			if (avail < size)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			rsa_pub_key.setExponent(mem.getBuffer(), base, size);
			base += size; // Skip Exp Value
			avail -= size;
			break;
		case KEY_RSA_PRIVATE:
			RSAPrivateKey rsa_prv_key = (RSAPrivateKey) getKey(key_nb, key_type, key_size);
			if (avail < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			size = mem.getShort(base);
			base += (short) 2; // Skip Mod Size
			avail -= (short) 2;
			if (avail < (short) (size + 2))
				ISOException.throwIt(SW_INVALID_PARAMETER);
			rsa_prv_key.setModulus(mem.getBuffer(), base, size);
			base += size; // Skip Mod Value
			avail -= size;
			// avail already checked in previous if ()
			size = mem.getShort(base);
			base += (short) 2; // Skip Exp Size
			avail -= (short) 2;
			if (avail < size)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			rsa_prv_key.setExponent(mem.getBuffer(), base, size);
			base += size; // Skip Exp Value
			avail -= size;
			break;
		case KEY_RSA_PRIVATE_CRT:
			RSAPrivateCrtKey rsa_prv_key_crt = (RSAPrivateCrtKey) getKey(key_nb, key_type, key_size);
			if (avail < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			size = mem.getShort(base);
			base += (short) 2; // Skip P Size
			avail -= (short) 2;
			if (avail < (short) (size + 2))
				ISOException.throwIt(SW_INVALID_PARAMETER);
			rsa_prv_key_crt.setP(mem.getBuffer(), base, size);
			base += size; // Skip P Value
			avail -= size;
			// avail ok...
			size = mem.getShort(base);
			base += (short) 2; // Skip Q Size
			avail -= (short) 2;
			if (avail < (short) (size + 2))
				ISOException.throwIt(SW_INVALID_PARAMETER);
			rsa_prv_key_crt.setQ(mem.getBuffer(), base, size);
			base += size; // Skip Q Value
			avail -= size;
			// avail ok...
			size = mem.getShort(base);
			base += (short) 2; // Skip PQ Size
			avail -= (short) 2;
			if (avail < (short) (size + 2))
				ISOException.throwIt(SW_INVALID_PARAMETER);
			rsa_prv_key_crt.setPQ(mem.getBuffer(), base, size);
			base += size; // Skip PQ Value
			avail -= size;
			// avail ok...
			size = mem.getShort(base);
			base += (short) 2; // Skip DP1 Size
			avail -= (short) 2;
			if (avail < (short) (size + 2))
				ISOException.throwIt(SW_INVALID_PARAMETER);
			rsa_prv_key_crt.setDP1(mem.getBuffer(), base, size);
			base += size; // Skip DP1 Value
			avail -= size;
			// avail ok...
			size = mem.getShort(base);
			base += (short) 2; // Skip DQ1 Size
			avail -= (short) 2;
			if (avail < size)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			rsa_prv_key_crt.setDQ1(mem.getBuffer(), base, size);
			base += size; // Skip DQ1 Value
			avail -= size;
			break;
		case KEY_DSA_PRIVATE:
			DSAPrivateKey dsa_prv_key = (DSAPrivateKey) getKey(key_nb, key_type, key_size);
			short num_bytes = DSAGetGPQ(mem.getBuffer(), base, avail, dsa_prv_key);
			base += num_bytes;
			avail -= num_bytes;
			if (avail < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			size = mem.getShort(base);
			base += (short) 2; // Skip X Size
			avail -= (short) 2;
			if (avail < size)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			dsa_prv_key.setX(mem.getBuffer(), base, size);
			base += size; // Skip X Value
			avail -= size;
			break;
		case KEY_DSA_PUBLIC:
			DSAPublicKey dsa_pub_key = (DSAPublicKey) getKey(key_nb, key_type, key_size);
			num_bytes = DSAGetGPQ(mem.getBuffer(), base, avail, dsa_pub_key);
			base += num_bytes;
			avail -= num_bytes;
			if (avail < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			size = mem.getShort(base);
			base += (short) 2; // Skip Y Size
			avail -= (short) 2;
			if (avail < size)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			dsa_pub_key.setY(mem.getBuffer(), base, size);
			base += size; // Skip Y Value
			avail -= size;
			break;
		case KEY_DES:
		case KEY_3DES:
		case KEY_3DES3:
			DESKey des_key = (DESKey) getKey(key_nb, key_type, key_size);
			if (avail < 2)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			size = mem.getShort(base);
			base += (short) 2; // Skip Key Size
			avail -= (short) 2;
			if (avail < size)
				ISOException.throwIt(SW_INVALID_PARAMETER);
			des_key.setKey(mem.getBuffer(), base);
			base += size; // Skip Key Value
			avail -= size;
			break;
		default:
			ISOException.throwIt(SW_INCORRECT_ALG);
		}
		// Zero and delete the import object
		om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
	}

	private void ExportKey(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_KEYS))
			ISOException.throwIt(SW_INCORRECT_P1);
		Key key = keys[key_nb];
		if ((key == null) || !key.isInitialized())
			ISOException.throwIt(SW_INCORRECT_P1);
		// Enforce Access Control
		if (!authorizeKeyRead(key_nb))
			ISOException.throwIt(SW_UNAUTHORIZED);
		// Destroy output object if already exists
		om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
		// Automatically throws SW_NO_MEMORY_LEFT
		short base = om.createObjectMax(OUT_OBJECT_CLA, OUT_OBJECT_ID, getCurrentACL(), (short) 0);
		short buffer_size = om.getSizeFromAddress(base);
		short avail = buffer_size; /*
									 * Initially holds buffer size, after is
									 * used to check buffer overflow
									 */
		/*** Start reading key blob ***/
		// Check Blob Encoding
		if (buffer[ISO7816.OFFSET_CDATA] != BLOB_ENC_PLAIN)
			ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
		// No need to check avail for all the key header
		if (avail < 4)
			ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
		mem.setByte(base, BLOB_ENC_PLAIN);
		base++; // Skip Blob Encoding
		// avail advanced below
		byte key_type = key.getType();
		mem.setByte(base, getKeyType(key));
		base++;
		// avail advanced below
		short key_size = key.getSize();
		mem.setShort(base, key_size);
		base += (short) 2; // Skip Key Size
		// keeps into account all the key header
		avail -= (short) 4;
		short size;
		/*
		 * Maximum size of a BigNumber estimated to be equal to the key size + 2
		 * bytes for the bignum size itself. TODO: Check if true for DSA
		 */
		short bn_size = (short) (keys[key_nb].getSize() / 8 + 2);
		switch (key_type) {
		case KeyBuilder.TYPE_RSA_PUBLIC:
			RSAPublicKey pub_key = (RSAPublicKey) key;
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = pub_key.getModulus(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip Modulus Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = pub_key.getExponent(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip Exponent Size & Value
			avail -= (short) (2 + size);
			break;
		case KeyBuilder.TYPE_RSA_PRIVATE:
			RSAPrivateKey prv_key = (RSAPrivateKey) key;
			if (avail < bn_size)
				ISOException.throwIt(SW_NO_MEMORY_LEFT);
			size = prv_key.getModulus(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip Modulus Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = prv_key.getExponent(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip Exponent Size & Value
			avail -= (short) (2 + size);
			break;
		case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
			RSAPrivateCrtKey prv_key_crt = (RSAPrivateCrtKey) key;
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = prv_key_crt.getP(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip P Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = prv_key_crt.getQ(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip Q Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = prv_key_crt.getPQ(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip PQ Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = prv_key_crt.getDP1(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip DP1 Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = prv_key_crt.getDQ1(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip DQ1 Size & Value
			avail -= (short) (2 + size);
			break;
		case KeyBuilder.TYPE_DES:
			DESKey des_key = (DESKey) key;
			/* For a DES Key, bn_size contains the exact key length + 2 */
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = des_key.getKey(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip P Size & Value
			avail -= (short) (2 + size);
			break;
		case KeyBuilder.TYPE_DSA_PUBLIC:
			DSAPublicKey dsa_pub_key = (DSAPublicKey) key;
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = dsa_pub_key.getG(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip G Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = dsa_pub_key.getP(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip P Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = dsa_pub_key.getQ(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip Q Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = dsa_pub_key.getY(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip Y Size & Value
			avail -= (short) (2 + size);
			break;
		case KeyBuilder.TYPE_DSA_PRIVATE:
			DSAPrivateKey dsa_prv_key = (DSAPrivateKey) key;
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = dsa_prv_key.getG(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip G Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = dsa_prv_key.getP(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip P Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = dsa_prv_key.getQ(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip Q Size & Value
			avail -= (short) (2 + size);
			if (avail < bn_size)
				ThrowDeleteObjects(SW_NO_MEMORY_LEFT);
			size = dsa_prv_key.getX(mem.getBuffer(), (short) (base + 2));
			mem.setShort(base, size);
			base += (short) (2 + size); // Skip X Size & Value
			avail -= (short) (2 + size);
			break;
		default:
			ISOException.throwIt(SW_INVALID_PARAMETER);
		}
		// Eventually clamp buffer to make the export object the exact
		// size of the exported key blob
		om.clampObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, (short) (buffer_size - avail));
	}

	private void CreatePIN(APDU apdu, byte[] buffer) {
		byte pin_nb = buffer[ISO7816.OFFSET_P1];
		byte num_tries = buffer[ISO7816.OFFSET_P2];
		/* Check that Identity n.0 is logged */
		if ((create_pin_ACL == (byte) 0xFF)
				|| (((logged_ids & create_pin_ACL) == (short) 0x0000) && (create_pin_ACL != (byte) 0x00)))
			ISOException.throwIt(SW_UNAUTHORIZED);
		if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS) || (pins[pin_nb] != null))
			ISOException.throwIt(SW_INCORRECT_P1);
		/* Allow pin lengths > 127 (useful at all ?) */
		short avail = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (apdu.setIncomingAndReceive() != avail)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		// At least 1 character for PIN and 1 for unblock code (+ lengths)
		if (avail < 4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		byte pin_size = buffer[ISO7816.OFFSET_CDATA];
		if (avail < (short) (1 + pin_size + 1))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		byte ucode_size = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pin_size)];
		if (avail != (short) (1 + pin_size + 1 + ucode_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), ucode_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		pins[pin_nb] = new OwnerPIN(num_tries, PIN_MAX_SIZE);
		pins[pin_nb].update(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size);
		ublk_pins[pin_nb] = new OwnerPIN((byte) 3, PIN_MAX_SIZE);
		// Recycle variable pin_size
		pin_size = (byte) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1);
		ublk_pins[pin_nb].update(buffer, pin_size, ucode_size);
	}

	private void VerifyPIN(APDU apdu, byte[] buffer) {
		byte pin_nb = buffer[ISO7816.OFFSET_P1];
		if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
			ISOException.throwIt(SW_INCORRECT_P1);
		OwnerPIN pin = pins[pin_nb];
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short numBytes = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		/*
		 * Here I suppose the PIN code is small enough to enter in the buffer
		 * TODO: Verify the assumption and eventually adjust code to support
		 * reading PIN in multiple read()s
		 */
		if (numBytes != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (!CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, (byte) numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (pin.getTriesRemaining() == (byte) 0x00)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);
		if (!pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) numBytes)) {
			LogoutIdentity(pin_nb);
			ISOException.throwIt(SW_AUTH_FAILED);
		}
		// Actually register that PIN has been successfully verified.
		logged_ids |= (short) (0x0001 << pin_nb);
	}

	private void ChangePIN(APDU apdu, byte[] buffer) {
		/*
		 * Here I suppose the PIN code is small enough that 2 of them enter in
		 * the buffer TODO: Verify the assumption and eventually adjust code to
		 * support reading PINs in multiple read()s
		 */
		byte pin_nb = buffer[ISO7816.OFFSET_P1];
		if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
			ISOException.throwIt(SW_INCORRECT_P1);
		OwnerPIN pin = pins[pin_nb];
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short avail = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (apdu.setIncomingAndReceive() != avail)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		// At least 1 charachter for each PIN code
		if (avail < 4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		byte pin_size = buffer[ISO7816.OFFSET_CDATA];
		if (avail < (short) (1 + pin_size + 1))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		byte new_pin_size = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pin_size)];
		if (avail < (short) (1 + pin_size + 1 + new_pin_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), new_pin_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (pin.getTriesRemaining() == (byte) 0x00)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);
		if (!pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size)) {
			LogoutIdentity(pin_nb);
			ISOException.throwIt(SW_AUTH_FAILED);
		}
		pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), new_pin_size);
		// JC specifies this resets the validated flag. So we do.
		logged_ids &= (short) ((short) 0xFFFF ^ (0x01 << pin_nb));
	}

	private void UnblockPIN(APDU apdu, byte[] buffer) {
		byte pin_nb = buffer[ISO7816.OFFSET_P1];
		if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
			ISOException.throwIt(SW_INCORRECT_P1);
		OwnerPIN pin = pins[pin_nb];
		OwnerPIN ublk_pin = ublk_pins[pin_nb];
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (ublk_pin == null)
			ISOException.throwIt(SW_INTERNAL_ERROR);
		// If the PIN is not blocked, the call is inconsistent
		if (pin.getTriesRemaining() != 0)
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		if (buffer[ISO7816.OFFSET_P2] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short numBytes = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		/*
		 * Here I suppose the PIN code is small enough to fit into the buffer
		 * TODO: Verify the assumption and eventually adjust code to support
		 * reading PIN in multiple read()s
		 */
		if (numBytes != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (!CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, (byte) numBytes))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!ublk_pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) numBytes))
			ISOException.throwIt(SW_AUTH_FAILED);
		pin.resetAndUnblock();
	}

	private void CreateObject(APDU apdu, byte[] buffer) {
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if ((create_object_ACL == (byte) 0xFF)
				|| (((logged_ids & create_object_ACL) == (short) 0x0000) && (create_object_ACL != (byte) 0x00)))
			ISOException.throwIt(SW_UNAUTHORIZED);
		// ID + Size + ACL = 14 bytes
		if (bytesLeft != (short) (4 + 4 + ObjectManager.OBJ_ACL_SIZE))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (buffer[ISO7816.OFFSET_P1] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		// Retrieve Object ID.
		short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 2));
		// Check if object exists
		if (om.exists(obj_class, obj_id))
			ISOException.throwIt(SW_OBJECT_EXISTS);
		// Check if object size in supported range: M.S.Word must be 0x0000 AND
		// M.S.Bit of L.S.Word must be 0
		if ((Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 4)) != 0x0000)
				|| (buffer[(short) (ISO7816.OFFSET_CDATA + 6)] < 0))
			ISOException.throwIt(SW_NO_MEMORY_LEFT);
		// Check for zero size
		if (Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 6)) == 0x0000)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Actually create object
		om.createObject(obj_class, obj_id,
		// Skip 2 M.S.Bytes of Size (only handle short sizes)
				Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 6)), buffer, (short) (ISO7816.OFFSET_CDATA + 8));
	}

	private void DeleteObject(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if ((buffer[ISO7816.OFFSET_P2] != (byte) 0x00) && (buffer[ISO7816.OFFSET_P2] != (byte) 0x01))
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (bytesLeft != (short) 0x04)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 2));
		// TODO: Here there are 2 object lookups. Optimize, please !
		// (single destroy function with logged_ids param)
		short base = om.getBaseAddress(obj_class, obj_id);
		// Verify that object exists
		if (base == MemoryManager.NULL_OFFSET)
			ISOException.throwIt(SW_OBJECT_NOT_FOUND);
		// Enforce Access Control
		if (!om.authorizeDeleteFromAddress(base, logged_ids))
			ISOException.throwIt(SW_UNAUTHORIZED);
		// Actually delete the object
		om.destroyObject(obj_class, obj_id, buffer[ISO7816.OFFSET_P2] == 0x01);
	}

	private void ReadObject(APDU apdu, byte[] buffer) {
		// Checking P1 & P2
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (bytesLeft != (short) 9)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 2));
		// Skip 2 M.S.Bytes of the offset
		short offset = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + (short) 6));
		short size = Util.makeShort((byte) 0x00, buffer[(short) ISO7816.OFFSET_CDATA + (short) 8]);
		short base = om.getBaseAddress(obj_class, obj_id);
		// Verify that object exists
		if (base == MemoryManager.NULL_OFFSET)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Enforce Access Control
		if (!om.authorizeReadFromAddress(base, logged_ids))
			ISOException.throwIt(SW_UNAUTHORIZED);
		/*
		 * Additional checks: buffer overflow protection (prevents reading
		 * memory contents following the object)
		 */
		if ((short) (offset + size) > om.getSizeFromAddress(base))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Sending data
		sendData(apdu, mem.getBuffer(), (short) (base + offset), size);
	}

	private void WriteObject(APDU apdu, byte[] buffer) {
		// Checking P1 & P2
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		short obj_id = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 2));
		// Skip 2 M.S.Bytes of the offset
		short offset = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 6));
		short size = Util.makeShort((byte) 0x00, buffer[(short) (ISO7816.OFFSET_CDATA + 8)]);
		short base = om.getBaseAddress(obj_class, obj_id);
		// Verify that object exists
		if (base == MemoryManager.NULL_OFFSET)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Enforce Access Control
		if (!om.authorizeWriteFromAddress(base, logged_ids))
			ISOException.throwIt(SW_UNAUTHORIZED);
		/*
		 * Additional checks: buffer overflow protection (prevents writing
		 * memory contents following the object)
		 */
		if ((short) (offset + size) > om.getSizeFromAddress(base))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Update object data
		mem.setBytes(base, offset, buffer, (short) (ISO7816.OFFSET_CDATA + 9), size);
	}

	private void LogOutAll() {
		logged_ids = (short) 0x0000; // Nobody is logged in
		byte i;
		for (i = (byte) 0; i < MAX_NUM_PINS; i++)
			if (pins[i] != null)
				pins[i].reset();
	}

	private void ListPINs(APDU apdu, byte[] buffer) {
		// Checking P1 & P2
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		byte expectedBytes = (byte) (buffer[ISO7816.OFFSET_LC]);
		if (expectedBytes != (short) 2)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		// Build the PIN bit mask
		short mask = (short) 0x00;
		short b;
		for (b = (short) 0; b < MAX_NUM_PINS; b++)
			if (pins[b] != null)
				mask |= (short) (((short) 0x01) << b);
		// Fill the buffer
		Util.setShort(buffer, (short) 0, mask);
		// Send response
		apdu.setOutgoingAndSend((short) 0, (short) 2);
	}

	private void ListObjects(APDU apdu, byte[] buffer) {
		// Checking P1 & P2
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		byte expectedBytes = (byte) (buffer[ISO7816.OFFSET_LC]);
		if (expectedBytes < ObjectManager.RECORD_SIZE)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		boolean found = false; // Suppress compiler warning
		if (buffer[ISO7816.OFFSET_P1] == LIST_OPT_RESET)
			found = om.getFirstRecord(buffer, (short) 0);
		else if (buffer[ISO7816.OFFSET_P1] != LIST_OPT_NEXT)
			ISOException.throwIt(SW_INCORRECT_P1);
		else
			found = om.getNextRecord(buffer, (short) 0);
		if (found)
			apdu.setOutgoingAndSend((short) 0, (short) ObjectManager.RECORD_SIZE);
		else
			ISOException.throwIt(SW_SEQUENCE_END);
	}

	private void ListKeys(APDU apdu, byte[] buffer) {
		// Checking P2
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short expectedBytes = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (expectedBytes != (short) 0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (buffer[ISO7816.OFFSET_P1] == LIST_OPT_RESET)
			key_it = (byte) 0;
		else if (buffer[ISO7816.OFFSET_P1] != LIST_OPT_NEXT)
			ISOException.throwIt(SW_INCORRECT_P1);
		while ((key_it < MAX_NUM_KEYS) && ((keys[key_it] == null) || !keys[key_it].isInitialized()))
			key_it++;
		if (key_it < MAX_NUM_KEYS) {
			Key key = keys[key_it];
			buffer[(short) 0] = key_it;
			buffer[(short) 1] = getKeyType(key);
			buffer[(short) 2] = (byte) 0xFF; // No partner information available
			Util.setShort(buffer, (short) 3, key.getSize());
			Util.arrayCopyNonAtomic(keyACLs, (short) (key_it * KEY_ACL_SIZE), buffer, (short) 5, KEY_ACL_SIZE);
			// Advance iterator
			key_it++;
			apdu.setOutgoingAndSend((short) 0, (short) (5 + KEY_ACL_SIZE));
		}
	}

	private void GetChallenge(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (bytesLeft < 4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		short size = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		short seed_size = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 2));
		if (bytesLeft != (short) (seed_size + 4))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		byte data_loc = buffer[ISO7816.OFFSET_P2];
		if ((data_loc != DL_APDU) && (data_loc != DL_OBJECT))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (randomData == null)
			randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		if (seed_size != (short) 0x0000)
			randomData.setSeed(buffer, (short) (ISO7816.OFFSET_CDATA + 4), seed_size);
		// Allow size = 0 for only seeding purposes
		if (size != (short) 0x0000) {
			// Automatically throws exception if no memory
			short base = om.createObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, (short) (size + 2), getRestrictedACL(),
					(short) 0);
			mem.setShort(base, size);
			randomData.generateData(mem.getBuffer(), (short) (base + 2), size);
			/*
			 * Remember that out object contains getChallenge data (to avoid
			 * attacks pretending to write the out object before extAuth)
			 */
			getChallengeDone = true;
			// Actually return data in APDU only if DL_APDU specified.
			if (data_loc == DL_APDU) {
				sendData(apdu, mem.getBuffer(), base, (short) (size + 2));
				/*
				 * Don't destroy out object ! Generated data is needed in
				 * ExtAuth !
				 */
				/* Not if running without external authentication */
				om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
			}
		}
	}

	private void ExternalAuthenticate(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (bytesLeft != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		byte key_nb = buffer[ISO7816.OFFSET_P1];
		if ((key_nb < 0) || (key_nb >= MAX_NUM_AUTH_KEYS) || (keys[key_nb] == null))
			ISOException.throwIt(SW_INCORRECT_P1);
		if (bytesLeft < 3)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		/* Verify that a GetChallenge has been issued */
		if (!getChallengeDone)
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		/*
		 * Clear getChallengeDone flag getChallengeDone = false; /* Retrieve
		 * getChallenge() data position and check it
		 */
		short chall_base = om.getBaseAddress(OUT_OBJECT_CLA, OUT_OBJECT_ID);
		if (chall_base == MemoryManager.NULL_OFFSET)
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		short obj_size = om.getSizeFromAddress(chall_base);
		if (obj_size < 3)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		short chall_size = mem.getShort(chall_base);
		/* Actually GetChallenge() creates an object of exact size */
		if (obj_size != (short) (2 + chall_size))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		byte ciph_mode = buffer[ISO7816.OFFSET_CDATA];
		byte ciph_dir = buffer[(short) (ISO7816.OFFSET_CDATA + 1)];
		byte[] src_buffer; /* The buffer of encrypted data */
		short src_offset; /* The offset of encrypted data in src_buffer[] */
		short src_avail; /* The available encrypted data (+ size) */
		switch (buffer[(short) (ISO7816.OFFSET_CDATA + 2)]) {
		case DL_APDU:
			src_buffer = buffer;
			src_offset = (short) (ISO7816.OFFSET_CDATA + 3);
			src_avail = (short) (bytesLeft - 3);
			break;
		case DL_OBJECT:
			src_offset = om.getBaseAddress(IN_OBJECT_CLA, IN_OBJECT_ID);
			if (src_offset == MemoryManager.NULL_OFFSET)
				ISOException.throwIt(SW_OBJECT_NOT_FOUND);
			src_buffer = mem.getBuffer();
			src_avail = om.getSizeFromAddress(src_offset);
		default:
			ISOException.throwIt(SW_INVALID_PARAMETER);
			return; // Suppress compiler warning
		}
		if (src_avail < 2)
			ISOException.throwIt(SW_INVALID_PARAMETER);
		short size = Util.getShort(src_buffer, src_offset);
		if (src_avail < (short) (size + 2))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		// Null key already checked above
		Key key = keys[key_nb];
		// Check if identity is actually blocked
		if (keyTries[key_nb] == (byte) 0)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);
		byte key_type = key.getType();
		boolean result = false;
		switch (ciph_dir) {
		case CD_DECRYPT:
			byte jc_ciph_alg;
			switch (ciph_mode) {
			case CM_RSA_NOPAD:
				if (key_type != KeyBuilder.TYPE_RSA_PUBLIC)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				jc_ciph_alg = Cipher.ALG_RSA_NOPAD;
				break;
			case CM_RSA_PAD_PKCS1:
				if (key_type != KeyBuilder.TYPE_RSA_PUBLIC)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				jc_ciph_alg = Cipher.ALG_RSA_PKCS1;
				break;
			case CM_DES_CBC_NOPAD:
				if (key_type != KeyBuilder.TYPE_DES)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				jc_ciph_alg = Cipher.ALG_DES_CBC_NOPAD;
				break;
			case CM_DES_ECB_NOPAD:
				if (key_type != KeyBuilder.TYPE_DES)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				jc_ciph_alg = Cipher.ALG_DES_ECB_NOPAD;
				break;
			default:
				ISOException.throwIt(SW_INVALID_PARAMETER);
				return; // Suppress compiler warning
			}
			Cipher ciph = getCipher(key_nb, jc_ciph_alg);
			ciph.init(key, Cipher.MODE_DECRYPT);
			// Create temporary buffer
			short temp = mem.alloc(chall_size);
			if (temp == MemoryManager.NULL_OFFSET)
				ISOException.throwIt(SW_NO_MEMORY_LEFT);
			short written_bytes = ciph.doFinal(src_buffer, (short) (src_offset + 2), size, mem.getBuffer(), temp);
			/*
			 * JC specifies that, when decrypting, padding bytes are cut out *
			 * so after a decrypt we should get the same size as the challenge*
			 * and they should be less than provided encrypted data
			 */
			if ((written_bytes == chall_size)
					&& (Util.arrayCompare(mem.getBuffer(), temp, mem.getBuffer(), (short) (chall_base + 2), chall_size) == (byte) 0))
				result = true;
			sendData(apdu, mem.getBuffer(), temp, written_bytes);
			mem.free(temp);
			break;
		case CD_VERIFY:
			byte jc_sign_alg;
			switch (ciph_mode) {
			case CM_DSA_SHA:
				if (key_type != KeyBuilder.TYPE_DSA_PUBLIC)
					ISOException.throwIt(SW_INVALID_PARAMETER);
				jc_sign_alg = Signature.ALG_DSA_SHA;
				break;
			default:
				ISOException.throwIt(SW_INVALID_PARAMETER);
				return; // Suppress compiler warning
			}
			Signature sign = getSignature(key_nb, jc_sign_alg);
			sign.init(key, Signature.MODE_VERIFY);
			if (sign.verify(mem.getBuffer(), (short) (chall_base + 2), chall_size, src_buffer,
					(short) (src_offset + 2), size))
				result = true;
			break;
		default:
			ISOException.throwIt(SW_INVALID_PARAMETER);
		}
		if (result) {
			LoginStrongIdentity(key_nb);
			// Reset try counter
			keyTries[key_nb] = MAX_KEY_TRIES;
			om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
			om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
		} else {
			// Decrease try counter
			keyTries[key_nb]--;
			LogoutIdentity((byte) (key_nb + 8));
			om.destroyObject(IN_OBJECT_CLA, IN_OBJECT_ID, true);
			om.destroyObject(OUT_OBJECT_CLA, OUT_OBJECT_ID, true);
			ISOException.throwIt(SW_AUTH_FAILED);
		}
	}

	private void GetStatus(APDU apdu, byte[] buffer) {
		if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short pos = (short) 0;
		buffer[pos++] = (byte) 1; // Major Card Edge Protocol version n.
		buffer[pos++] = (byte) 3; // Minor Card Edge Protocol version n.
		buffer[pos++] = (byte) 0; // Major Applet version n.
		buffer[pos++] = (byte) 9; // Minor Applet version n.
		Util.setShort(buffer, pos, (short) 0x00); // Total mem M.S.
		pos += (short) 2;
		Util.setShort(buffer, pos, (short) mem.getBuffer().length); // Total mem
		// L.S.
		pos += (short) 2;
		Util.setShort(buffer, pos, (short) 0x00); // Free mem M.S.
		pos += (short) 2;
		Util.setShort(buffer, pos, mem.freemem()); // Free mem L.S.
		pos += (short) 2;
		byte cnt = (byte) 0;
		for (short i = 0; i < pins.length; i++)
			if (pins[i] != null)
				cnt++;
		buffer[pos++] = cnt; // Number of used PINs
		cnt = (byte) 0;
		for (short i = 0; i < keys.length; i++)
			if (keys[i] != null)
				cnt++;
		buffer[pos++] = cnt; // Number of used Keys
		Util.setShort(buffer, pos, logged_ids); // Logged ids
		pos += (short) 2;
		apdu.setOutgoingAndSend((short) 0, pos);
	}
} // end of class JAVA_APPLET
