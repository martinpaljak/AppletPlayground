/*
 * Java Card PKI applet - ISO7816 compliant Java Card applet.
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
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
 *
 */

package pro.javacard.applets;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import visa.openplatform.OPSystem;

/**
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 * 
 */
public class PKIApplet extends Applet implements ISO7816 {

	/** CLAss byte masks */
	private static final byte CLA_CHAIN = 0x10;
	private static final byte CLA_SM = 0x0C;

	/** INStructions */
	private static final byte INS_READBINARY = (byte)0xB0;
	private static final byte INS_VERIFY = (byte)0x20;
	private static final byte INS_CHANGEREFERENCEDATA = (byte)0x24;
	private static final byte INS_GETCHALLENGE = (byte)0x84;
	private static final byte INS_MSE = (byte)0x22;
	private static final byte INS_PSO = (byte)0x2A;
	private static final byte INS_INTERNALAUTHENTICATE = (byte)0x88;
	private static final byte INS_WRITEBINARY = (byte)0xD0;
	private static final byte INS_CREATEFILE = (byte)0xE0;
	private static final byte INS_PUTDATA = (byte)0xDA;
	private static final byte INS_GENERATE_KEY_PAIR = (byte)0x46;

	/** Other constants */
	private static final byte MASK_SFI = (byte)0x80;
	private static final byte MAX_PIN_SIZE = 20;
	private static final byte MIN_PIN_SIZE = 4;
	private static final byte PIN_TRIES = 3;
	private static final byte PUC_SIZE = 16;
	private static final byte PUC_TRIES = 3;

	private static final byte ALG_AUTH_DEC_RSA = (byte)0x01;
	private static final byte ALG_SIGN_RSA_PKCS1_SHA1 = (byte)0x02;
	private static final byte ALG_SIGN_RSA_PKCS1_SHA256 = (byte)0x03;
	private static final byte ALG_SIGN_RSA_PSS = (byte)0x04;
	private static final byte ALG_SIGN_RSA_PKCS1_SHA1MD5 = (byte)0x05;

	private static final short MAX_BLOCK_LEN = 256;
	private static final short C_LEN = 4;
	private static final short SHA1_LEN = 20;
	private static final short SHA256_LEN = 32;
	private static final short SHA1MD5_LEN = 36;


	/** SW-s not defined in the ISO7816 interface */
	private static final short SW_END_OF_FILE = (short)0x6282;
	private static final short SW_PIN_INCORRECT_TRIES_LEFT = (short)0x63C0;
	private static final short SW_KEY_NOT_FOUND = (short)0x6A88;
	private static final short SW_LAST_COMMAND_EXPECTED = (short)0x6883;
	private static final short SW_SECURE_MESSAGING_NOT_SUPPORTED = (short)0x6882;

	/** For calculation of the PSS scheme */
	private static final short TMP_OFFSET = 0;
	private static final short TMP_HASH_OFFSET = TMP_OFFSET + MAX_BLOCK_LEN;
	private static final short TMP_C_OFFSET = TMP_HASH_OFFSET + SHA1_LEN;
	private static final short TMP_SIGNALG_OFFSET = TMP_C_OFFSET + C_LEN;
	private static final short TMP_DECSEQ_OFFSET = TMP_SIGNALG_OFFSET + 1;
	private static final short TMP_SIZE = TMP_DECSEQ_OFFSET + 1;

	/** Life states of the applet */
	private static final byte STATE_INITIAL = 1;   // Before files are written, hist bytes are set, the puc is set
	private static final byte STATE_PREPERSONALISED = 2; // Before the pin is set
	private static final byte STATE_PERSONALISED = 3;  // pin is set, ready to use

	private FileSystem fileSystem = null;
	private OwnerPIN pin = null;
	private OwnerPIN puc = null;

	private RandomData rd = null;
	private Cipher pkcs1Cipher = null;
	private Cipher nopadCipher = null;
	private MessageDigest md = null;
	private byte state = 0;

	private RSAPrivateCrtKey authKeyPrivate = null;
	private RSAPrivateCrtKey signKeyPrivate = null;
	private byte signKeyFirstModulusByte = 0;
	private RSAPrivateCrtKey decKeyPrivate = null;
	private RSAPublicKey tempKeyPublic = null;

	private Object[] currentPrivateKey = null;
	private byte[] tmp = null;

	private short[] expectedDecipherDataLength = null;

	private byte[] authKeyId = null;
	private byte[] signKeyId = null;
	private byte[] decKeyId = null;
	private static final short KEY_ID_SIZE = 17; // Len + 16 bytes of data

	private final static byte[] myAID = new byte[] { (byte) 0xA0, 0x00, 0x00, 0x00,
		0x63, 0x50, 0x4B, 0x43, 0x053, 0x2D, 0x31, 0x35 };

	public static void install(byte[] bArray, short bOffset, byte bLength) throws SystemException {
		new PKIApplet().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}

	public void deselect() {
		pin.reset();
		puc.reset();
	}

	private PKIApplet() {
		pin = new OwnerPIN(PIN_TRIES, MAX_PIN_SIZE);
		puc = new OwnerPIN(PUC_TRIES, PUC_SIZE);
		rd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		pkcs1Cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		nopadCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
		md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		tmp = JCSystem.makeTransientByteArray(TMP_SIZE,  JCSystem.CLEAR_ON_DESELECT);
		state = STATE_INITIAL;
		authKeyId = new byte[KEY_ID_SIZE];
		signKeyId = new byte[KEY_ID_SIZE];
		decKeyId = new byte[KEY_ID_SIZE];
		authKeyPrivate = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
		signKeyPrivate = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
		decKeyPrivate = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
		tempKeyPublic = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
		currentPrivateKey = JCSystem.makeTransientObjectArray((short)1, JCSystem.CLEAR_ON_DESELECT);
		expectedDecipherDataLength = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
		fileSystem = new FileSystem((short)16);
	}

	public void process(APDU apdu) {

		byte[] buf = apdu.getBuffer();
		byte cla = buf[OFFSET_CLA];
		byte ins = buf[OFFSET_INS];

		// No secure messaging for the PKI applet
		if((byte)(cla & CLA_SM) == CLA_SM) {
			ISOException.throwIt(SW_SECURE_MESSAGING_NOT_SUPPORTED);
		}
		// Only PSO can be chained
		if (!(cla == CLA_ISO7816
				|| (cla == CLA_CHAIN && ins == INS_PSO))) {
			ISOException.throwIt(SW_CLA_NOT_SUPPORTED);
		}
		switch (ins) {
		case INS_SELECT:
			processSelectFile(apdu);
			break;
		case INS_READBINARY:
			processReadBinary(apdu);
			break;
		case INS_WRITEBINARY:
			processWriteBinary(apdu);
			break;
		case INS_VERIFY:
			processVerify(apdu);
			break;
		case INS_CHANGEREFERENCEDATA:
			processChangeReferenceData(apdu);
			break;
		case INS_PUTDATA:
			processPutData(apdu);
			break;
		case INS_GENERATE_KEY_PAIR:
			processGenerateAssymetricKeyPair(apdu);
			break;
		case INS_CREATEFILE:
			processCreateFile(apdu);
			break;
		case INS_GETCHALLENGE:
			processGetChallenge(apdu);
			break;
		case INS_MSE:
			processManageSecurityEnvironment(apdu);
			break;
		case INS_PSO:
			processPerformSecurityOperation(apdu);
			break;
		case INS_INTERNALAUTHENTICATE:
			processInternalAuthenticate(apdu);
			break;
		default:
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
	}

	/**
	 * Process the SELECT (file) instruction (0xA4)
	 * ISO7816-4 Section 7.1.1
	 *
	 */
	private void processSelectFile(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		//byte p2 = buf[OFFSET_P2];
		short lc = unsigned(buf[OFFSET_LC]);

		if(p1 == 0x04) {
			// Select the AID of the applet
			// do heavy verification, just for the fun of it ;)
			if (lc != (short) 0x0C) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			apdu.setIncomingAndReceive();
			if (Util.arrayCompare(buf, OFFSET_CDATA, myAID, (short) 0, lc) != 0) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			return ;
		}

		short id = 0;
		switch (p1) {
		case (byte) 0x00:
			// Direct selection of MF, DF, or EF:
			if (lc != 0 && lc != 2) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
		if (lc > 0) {
			apdu.setIncomingAndReceive();
			id = Util.makeShort(buf[OFFSET_CDATA],
					buf[(short) (OFFSET_CDATA + 1)]);
		} else {
			id = FileSystem.MASTER_FILE_ID;
		}
		if (!fileSystem.selectEntryAbsolute(id)) {
			ISOException.throwIt(SW_FILE_NOT_FOUND);
		}
		break;
		case (byte) 0x01:
		case (byte) 0x02:
			// Select the child under the current DF,
			// p1 0x01 DF identifier in data field
			// p1 0x02 EF identifier in data field
			if (lc != 2) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
		apdu.setIncomingAndReceive();
		id = Util.makeShort(buf[OFFSET_CDATA],
				buf[(short) (OFFSET_CDATA + 1)]);
		if (!fileSystem.selectEntryUnderCurrent(id, p1 == (byte) 0x02)) {
			ISOException.throwIt(SW_FILE_NOT_FOUND);
		}
		break;
		case (byte) 0x03:
			// Select the parent of the current DF
			// no command data
			if (lc != 0) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
		if (!fileSystem.selectEntryParent()) {
			ISOException.throwIt(SW_FILE_NOT_FOUND);
		}
		break;
		case (byte) 0x08:
		case (byte) 0x09:
			// Select by path
			// p1 0x08 from MF
			// p1 0x09 from current DF
			// data field: the path without the head
			if (lc == 0 || (short) (lc % 2) != 0) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
		apdu.setIncomingAndReceive();
		if (!fileSystem.selectEntryByPath(buf, OFFSET_CDATA, lc,
				p1 == (byte) 0x08)) {
			ISOException.throwIt(SW_FILE_NOT_FOUND);
		}
		break;
		default:
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
	}

	/**
	 * Process the READ BINARY instruction (0xB0)
	 * ISO7816-4 Section 7.2.3
	 * 
	 * We handle only the INS == 0xB0 case.
	 *
	 */
	private void processReadBinary(APDU apdu) {
		if(state != STATE_PERSONALISED) {
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];
		short offset = 0;
		short ef = -1;
		if((byte)(p1 & MASK_SFI) == MASK_SFI) {
			byte sfi = (byte)(p1 & ~MASK_SFI);
			if(sfi >= 0x1F) {
				ISOException.throwIt(SW_INCORRECT_P1P2);
			}
			ef = fileSystem.findCurrentSFI(sfi);
			if(ef == -1) {
				ISOException.throwIt(SW_FILE_NOT_FOUND);
			}
			ef = fileSystem.fileStructure[ef];
			offset = unsigned(p2);
		}else{
			ef = fileSystem.getCurrentIndex();
			if(fileSystem.getFile(ef) == null) {
				ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
			}
			offset = Util.makeShort(p1, p2);
		}
		byte[] file = fileSystem.getFile(ef);
		if(offset > file.length) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
		if(fileSystem.getPerm(ef) == FileSystem.PERM_PIN && !pin.isValidated()) {
			ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		short le = apdu.setOutgoing();
		if(le == 0 || le == 256) {
			le = (short)(file.length - offset);
			if(le > 256) le = 256;
		}
		boolean eof = false;
		if((short)(file.length - offset) < le) {
			le = (short)(file.length - offset);
			eof = true;
		}
		apdu.setOutgoingLength(le);
		apdu.sendBytesLong(file, offset, le);
		if(eof) {
			ISOException.throwIt(SW_END_OF_FILE);
		}
	}

	/**
	 * Process the VERIFY instruction (0x20)
	 * ISO7816-4 Section 7.5.6
	 * 
	 */
	private void processVerify(APDU apdu) {
		if(state != STATE_PERSONALISED) {
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
		byte[] buf = apdu.getBuffer();
		if(buf[OFFSET_P1] != 0x00 || buf[OFFSET_P2] != 0x00) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
		short lc = unsigned(buf[OFFSET_LC]);
		if(lc < MIN_PIN_SIZE || lc > MAX_PIN_SIZE) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setIncomingAndReceive();
		// Pad the PIN to overwrite any possible garbage in the APDU (e.g. Le)
		Util.arrayFillNonAtomic(buf, (short)(OFFSET_CDATA+lc),
				(short)(MAX_PIN_SIZE - lc), (byte)0x00);
		if(!pin.check(buf, OFFSET_CDATA, MAX_PIN_SIZE)) {
			ISOException.throwIt((short)(SW_PIN_INCORRECT_TRIES_LEFT | pin.getTriesRemaining()));
		}
	}

	/**
	 * Process the CHANGE REFERENCE DATA instruction (0x24)
	 * ISO7816-4 Section 7.5.7
	 * 
	 * We have two options here: (a) in a procudction state we can
	 * set the PUC with this, (b) in the distribution state and operational
	 * state we change the PIN
	 */
	private void processChangeReferenceData(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		short lc = unsigned(buf[OFFSET_LC]);
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];
		if(state > STATE_INITIAL) {
			// We are changing the PIN, PUC has to be provided
			// check that P1 is 0x00: verification data (puc) followed by new reference data (pin)
			if(p1 != 0x00 || p2 != (byte)0x00) {
				ISOException.throwIt(SW_INCORRECT_P1P2);
			}
			short pinSize = (short)(lc - PUC_SIZE);
			if(pinSize < MIN_PIN_SIZE || pinSize > MAX_PIN_SIZE) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			apdu.setIncomingAndReceive();
			short offset = (short)(OFFSET_CDATA+PUC_SIZE);
			for(short i=0;i<pinSize;i++) {
				byte b = buf[(short)(offset+i)];
				if(b < (byte)0x30 || b > (byte)0x39) {
					ISOException.throwIt(SW_WRONG_DATA);
				}
			}
			// Pad the pin with 0x00 to overwrite any garbage, e.g. le
			Util.arrayFillNonAtomic(buf, (short)(offset+pinSize), (short)(MAX_PIN_SIZE - pinSize), (byte)0x00);
			if(!puc.check(buf, OFFSET_CDATA, PUC_SIZE)) {
				ISOException.throwIt((short)(SW_PIN_INCORRECT_TRIES_LEFT | puc.getTriesRemaining()));
			}
			pin.update(buf, offset, MAX_PIN_SIZE);
			pin.resetAndUnblock();
			if(state == STATE_PREPERSONALISED) {
				state = STATE_PERSONALISED;
			}
		}else{
			// State is production, we set the puc
			if(p1 != 0x01 || p2 != 0x00) {
				ISOException.throwIt(SW_INCORRECT_P1P2);
			}
			if(lc != PUC_SIZE) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			apdu.setIncomingAndReceive();
			puc.update(buf, OFFSET_CDATA, (byte)lc);
			puc.resetAndUnblock();
		}
	}

	/**
	 * Process the PUT DATA instruction (0xDA)
	 * P1 and P2 are custom
	 * 
	 */
	private void processPutData(APDU apdu) {
		byte p1 = apdu.getBuffer()[OFFSET_P1];
		if(p1 >= (byte)0x61 && p1 <= (byte)0x66) {
			processSetupKey(apdu);
		}else if(p1 == (byte)0x67) {
			processSetHistoricalBytes(apdu);
		}else if(p1 == (byte)0x68) {
			processSetState(apdu);
		}else if(p1 == (byte)0x69) {
			processCreateFileSystemStructure(apdu);
		}else{
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
	}

	/**
	 * Process the GET CHALLENGE instruction (0x84)
	 * ISO 7816-4, Section 7.5.3
	 * 
	 */
	private void processGetChallenge(APDU apdu) {
		if(state != STATE_PERSONALISED) {
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
		byte[] buf = apdu.getBuffer();

		if(buf[OFFSET_P1] != 0x00 || buf[OFFSET_P2] != 0x00) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
		short le = apdu.setOutgoing();
		if(le == 0) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setOutgoingLength(le);
		rd.generateData(buf, (short)0, le);
		apdu.sendBytes((short)0, le);
	}

	/** Process the MANAGE SECURITY ENVIRONMENT instruction (0x22).
	 *  ISO7816-4, Section 7.5.11
	 * 
	 *  This command can be also used to prepare key generation.
	 *  In this case the algorithm indication is not required, in
	 *  fact, should not be present. Note that the
	 *  key identifiers should be already set up with put data before that.
	 */
	private void processManageSecurityEnvironment(APDU apdu) {
		boolean forKeyGeneration = false;
		if(state == STATE_INITIAL) {
			forKeyGeneration = true;
		}else if(state == STATE_PREPERSONALISED) {
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
		pin.reset();
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];
		// P1 should be:
		// (a) 0x40: computation, decipherment, internal authentication, ...
		// (b) 0x01: set
		if(p1 != (byte)0x41) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
		byte[] expectedKeyId = null;
		// P2 should be one of the following, see ISO7816-4 Table 79
		if(p2 == (byte)0xa4) {
			expectedKeyId = authKeyId;
		}else if (p2 == (byte)0xb6) {
			expectedKeyId = signKeyId;
		}else if (p2 == (byte)0xB8) {
			expectedKeyId = decKeyId;
		}else{
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
		short lc = unsigned(buf[OFFSET_LC]);
		if(lc == 0) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setIncomingAndReceive();
		short offset = OFFSET_CDATA;
		lc += OFFSET_CDATA;
		// Tag for the private key:
		short len = checkDataObject(buf, offset, lc, (byte)0x84);
		offset += 2;
		if(len != expectedKeyId[0]) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		if(Util.arrayCompare(buf, offset, expectedKeyId, (short)1, len) != 0) {
			ISOException.throwIt(SW_KEY_NOT_FOUND);
		}
		offset += len;


		// Algorithm identfier tag
		if(!forKeyGeneration) {
			if(offset >= lc) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			len = checkDataObject(buf, offset, lc, (byte)0x80);
			offset += 2;
			if(len != 1) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			byte sAlg = buf[offset++];
			if(offset != lc) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			if(sAlg < ALG_AUTH_DEC_RSA || sAlg > ALG_SIGN_RSA_PKCS1_SHA1MD5) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			tmp[TMP_SIGNALG_OFFSET] = sAlg;
		}else{
			if(offset != lc) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
		}
		if(expectedKeyId == authKeyId) {
			currentPrivateKey[0] = authKeyPrivate;
		}else if(expectedKeyId == signKeyId) {
			currentPrivateKey[0] = signKeyPrivate;
		}else if(expectedKeyId == decKeyId) {
			currentPrivateKey[0] = decKeyPrivate;
		}

	}

	// Checks the DO in the buffer, report any inconsitencies
	// Return the length of the data
	private short checkDataObject(byte[] buffer, short offset, short lastOffset, byte expectedTag) {
		if(offset >= lastOffset || lastOffset > buffer.length) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		if(buffer[offset++] != expectedTag) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		short len = unsigned(buffer[offset++]);
		if(offset  > (short)(lastOffset - len)) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		return len;
	}

	/**
	 * Generate an assymetric RSA key pair according to ISO7816-8,
	 * Section 5.1. We only support RSA 1024 bit at the moment, and
	 * return data in simple TLV data objects, tags 81 and 82.
	 * 
	 * Successful MSE command has to be performed prior to this one.
	 */
	private void processGenerateAssymetricKeyPair(APDU apdu) {
		// This is only valid in state initial (at the moment)
		if(state != STATE_INITIAL) {
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];
		if(p1 != (byte)0x80 || p2 != (byte)0x00) {
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
		if(currentPrivateKey[0] == null) {
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}
		KeyPair pair = new KeyPair(tempKeyPublic, (RSAPrivateCrtKey)currentPrivateKey[0]);
		pair.genKeyPair();
		// Sanity check, the KeyPair class should regenerate the keys "in place".
		if(pair.getPrivate() != currentPrivateKey[0] || pair.getPublic() != tempKeyPublic) {
			ISOException.throwIt(SW_DATA_INVALID);
		}
		apdu.setOutgoing();
		short len = (short)0;
		short offset = 0;
		buf[offset++] = (byte)0x81;
		len = tempKeyPublic.getModulus(buf, (short)(offset+2));
		buf[offset++] = (byte)0x81;
		buf[offset++] = (byte)len;
		offset += len;
		buf[offset++] = (byte)0x82;
		len = tempKeyPublic.getExponent(buf, (short)(offset+1));
		buf[offset++] = (byte)len;
		offset += len;
		apdu.setOutgoingLength(offset);
		apdu.sendBytes((short)0, offset);
	}


	/**
	 * Process the PERFORM SECURITY OPERATION instruction (0x2A).
	 * ISO 7816-8 Section 5.2
	 */
	private void processPerformSecurityOperation(APDU apdu) {
		if(state != STATE_PERSONALISED) {
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
		if(!pin.isValidated()) {
			ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];
		if(p1 == (byte)0x80 && (p2 == (byte)0x82 || p2 == (byte)0x84 || p2 == (byte)0x86)) {
			processDecipher(apdu);
		}else if(p1 == (byte)0x9E && p2 == (byte)0x9A) {
			processComputeDigitalSignature(apdu);
		}else{
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
	}

	/**
	 * Process the PSO DECIPHER instruction.
	 * ISO 7816-8 Section 5.10
	 * 
	 */
	private void processDecipher(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		byte cla = buf[OFFSET_CLA];
		boolean chain = ((byte)(cla & CLA_CHAIN) == CLA_CHAIN);
		short lc = unsigned(buf[OFFSET_LC]);

		// We need at least 1 byte of data to feed into the cipher,
		// so that a progression is made
		if(lc == 0) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setIncomingAndReceive();
		short offset = OFFSET_CDATA;

		// The first in chain, intialized and check:
		if(tmp[TMP_DECSEQ_OFFSET] == (byte)0x00) {
			RSAPrivateCrtKey key = (RSAPrivateCrtKey)currentPrivateKey[0];
			if(key == null) {
				ISOException.throwIt(SW_KEY_NOT_FOUND);
			}
			byte alg = tmp[TMP_SIGNALG_OFFSET];
			if(key != decKeyPrivate || alg != ALG_AUTH_DEC_RSA) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			pkcs1Cipher.init(key, Cipher.MODE_DECRYPT);
			tmp[TMP_DECSEQ_OFFSET]++;
			expectedDecipherDataLength[0] = (short)(key.getSize()/8);
		}

		short decipheredLen = 0;
		try {
			decipheredLen = pkcs1Cipher.update(buf, offset, lc, tmp, (short)(TMP_OFFSET + decipheredLen));
		}catch(CryptoException ce) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		expectedDecipherDataLength[0] -= lc;
		offset += lc;

		// Data still to come:
		if(expectedDecipherDataLength[0] != 0 && !chain) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		// No more data:
		if(expectedDecipherDataLength[0] == 0 && chain) {
			ISOException.throwIt(SW_LAST_COMMAND_EXPECTED);
		}

		if(chain) {
			// It should also be the case the deciphereLen == 0, check?
			return;
		}
		pin.reset();
		tmp[TMP_DECSEQ_OFFSET] = 0x00;
		try {
			decipheredLen = pkcs1Cipher.doFinal(buf, offset, (short)0, tmp, (short)(TMP_OFFSET + decipheredLen));
		}catch(CryptoException ce) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		Util.arrayCopyNonAtomic(tmp, TMP_OFFSET, buf, (short)0, decipheredLen);
		apdu.setOutgoingAndSend((short)0, decipheredLen);
	}

	/**
	 * Process the PSO COMPUTE DIGITAL SIGNATURE instruction (0x2A)
	 * ISO 7816-8 Section 5.4
	 * 
	 */
	private void processComputeDigitalSignature(APDU apdu) {
		pin.reset();
		byte[] buf = apdu.getBuffer();
		short lc = unsigned(buf[OFFSET_LC]);
		if(lc == 0) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setIncomingAndReceive();

		RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey)currentPrivateKey[0];
		byte alg = tmp[TMP_SIGNALG_OFFSET];
		if(privateKey != signKeyPrivate || (alg != ALG_SIGN_RSA_PKCS1_SHA1 && alg != ALG_SIGN_RSA_PKCS1_SHA256 && alg != ALG_SIGN_RSA_PSS && alg != ALG_SIGN_RSA_PKCS1_SHA1MD5)) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		short offset = OFFSET_CDATA;
		short expectedLength = 0;
		if(alg == ALG_SIGN_RSA_PKCS1_SHA256) {
			expectedLength = (short)(SHA256_LEN + 17);
		}else if(alg == ALG_SIGN_RSA_PKCS1_SHA1) {
			expectedLength = (short)(SHA1_LEN + 13);
		}else if(alg == ALG_SIGN_RSA_PSS) {
			expectedLength = SHA1_LEN;
		}else if(alg == ALG_SIGN_RSA_PKCS1_SHA1MD5) {
			expectedLength = SHA1MD5_LEN;
		}
		if(lc != expectedLength) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		short sigLen = 0;
		if(alg == ALG_SIGN_RSA_PKCS1_SHA1 || alg == ALG_SIGN_RSA_PKCS1_SHA256 || alg == ALG_SIGN_RSA_PKCS1_SHA1MD5) {
			pkcs1Cipher.init(privateKey, Cipher.MODE_ENCRYPT);
			sigLen = pkcs1Cipher.doFinal(buf, offset, lc, tmp, TMP_OFFSET);
			Util.arrayCopyNonAtomic(tmp, TMP_OFFSET, buf, (short)0, sigLen);
		}else{
			short emLen = (short)(privateKey.getSize() / 8);
			pssPad(buf, offset, lc, tmp, TMP_OFFSET, emLen, signKeyFirstModulusByte);
			nopadCipher.init(privateKey, Cipher.MODE_ENCRYPT);
			sigLen = nopadCipher.doFinal(tmp, (short)0, emLen, buf, (short)0);
		}
		apdu.setOutgoingAndSend((short)0, sigLen);

	}

	/**
	 * Process the INTERNAL AUTHENTICATE instruction (0x88)
	 * ISO 7816-4 Section 7.5.2
	 * 
	 */
	private void processInternalAuthenticate(APDU apdu) {
		if(state != STATE_PERSONALISED) {
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
		if(!pin.isValidated()) {
			ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		byte[] buf = apdu.getBuffer();
		short lc = unsigned(buf[OFFSET_LC]);
		if(lc == 0) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setIncomingAndReceive();

		RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey)currentPrivateKey[0];
		byte alg = tmp[TMP_SIGNALG_OFFSET];
		if(privateKey != authKeyPrivate || alg != ALG_AUTH_DEC_RSA) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		short offset = OFFSET_CDATA;
		short maxLength = (short)((short)(privateKey.getSize() / 8) - 11);
		if(lc > maxLength) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		pkcs1Cipher.init(privateKey, Cipher.MODE_ENCRYPT);
		short len = pkcs1Cipher.doFinal(buf, offset, lc, tmp, TMP_OFFSET);
		Util.arrayCopyNonAtomic(tmp, TMP_OFFSET, buf, (short)0, len);
		apdu.setOutgoingAndSend((short)0, len);
	}


	private void processSetHistoricalBytes(APDU apdu) {
		if(state != STATE_INITIAL) {
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}
		byte[] buf = apdu.getBuffer();
		byte lc = buf[OFFSET_LC];
		if(lc <= 0) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setIncomingAndReceive();
		// Was GPSystem
		OPSystem.setATRHistBytes(buf, OFFSET_CDATA, lc);
	}

	private void processCreateFileSystemStructure(APDU apdu) {
		if(state != STATE_INITIAL) {
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}
		byte[] buf = apdu.getBuffer();
		short lc = unsigned(buf[OFFSET_LC]);
		apdu.setIncomingAndReceive();
		// Hack:
		// Search for a non-existing file,
		// if the structure is correct, then only the FileNotFoundException would be
		// thrown.
		try {
			fileSystem.searchId(buf, OFFSET_CDATA, OFFSET_CDATA, (short)(OFFSET_CDATA + lc), (short)0x0000);
			ISOException.throwIt(SW_WRONG_DATA);
		}catch(FileNotFoundException e) {
		}catch(ArrayIndexOutOfBoundsException aioobe) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		fileSystem.fileStructure = new byte[lc];
		Util.arrayCopy(buf, OFFSET_CDATA, fileSystem.fileStructure, (short)0, lc);
	}

	private void processCreateFile(APDU apdu) {
		if(state != STATE_INITIAL) {
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
		byte[] buf = apdu.getBuffer();
		short lc = unsigned(buf[OFFSET_LC]);
		apdu.setIncomingAndReceive();
		if(lc != 5) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		short offset = OFFSET_CDATA;
		short id = Util.getShort(buf, offset);
		offset += 2;
		short len = Util.getShort(buf, offset);
		offset += 2;
		byte perm = buf[offset];
		if(!fileSystem.createFile(id, len, perm)) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
	}

	private void processSetState(APDU apdu) throws ISOException {
		if(state == STATE_PERSONALISED) {
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}
		byte p2 = apdu.getBuffer()[OFFSET_P2];
		if(p2 != STATE_INITIAL && p2 != STATE_PREPERSONALISED) {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		state = p2;
	}

	/**
	 * Process the WRITE BINARY Instruction (0xD0).
	 * ISO7816-4 Section 7.2.4
	 *
	 */
	private void processWriteBinary(APDU apdu) throws ISOException {
		if(state != STATE_INITIAL) {
			ISOException.throwIt(SW_INS_NOT_SUPPORTED);
		}
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];
		short offset = 0;
		short ef = -1;
		if((byte)(p1 & MASK_SFI) == MASK_SFI) {
			byte sfi = (byte)(p1 | ~MASK_SFI);
			if(sfi >= 0x1F) {
				ISOException.throwIt(SW_INCORRECT_P1P2);
			}
			ef = fileSystem.findCurrentSFI(sfi);
			if(ef == -1) {
				ISOException.throwIt(SW_FILE_NOT_FOUND);
			}
			ef = fileSystem.fileStructure[ef];
			offset = unsigned(p2);
		}else{
			ef = fileSystem.getCurrentIndex();
			if(fileSystem.getFile(ef) == null) {
				ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
			}
			offset = Util.makeShort(p1, p2);
		}
		byte[] file = fileSystem.getFile(ef);
		short lc = unsigned(buf[OFFSET_LC]);
		if((short)(offset + lc) > file.length) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}
		apdu.setIncomingAndReceive();
		Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, file, offset, lc);
	}

	private void processSetupKey(APDU apdu) throws ISOException {
		if(state != STATE_INITIAL) {
			ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
		}
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[OFFSET_P1];
		byte p2 = buf[OFFSET_P2];
		short lc = unsigned(buf[OFFSET_LC]);
		apdu.setIncomingAndReceive();
		if(p1 == (byte)0x61 || p1 == (byte)0x62 || p1 == (byte)0x63) {
			if(lc > 16) {
				ISOException.throwIt(SW_WRONG_LENGTH);
			}
			byte[] keyId = null;
			if(p1 == (byte)0x61) {
				keyId = authKeyId;
			}else if(p1 == (byte)0x62) {
				keyId = signKeyId;
			}else if(p1 == (byte)0x63) {
				keyId = decKeyId;
			}
			Util.arrayCopy(buf, OFFSET_CDATA, keyId, (short)1, lc);
			keyId[0] = (byte)lc;
			return;
		}
		RSAPrivateCrtKey privKey = null;
		if(p1 == (byte)0x64) {
			privKey = authKeyPrivate;
		}else if(p1 == (byte)0x65){
			privKey = signKeyPrivate;
		}else if(p1 == (byte)0x66) {
			privKey = decKeyPrivate;
		}else{
			ISOException.throwIt(SW_INCORRECT_P1P2);
		}
		try {
			switch(p2) {
			case (byte)0x81: // Modulus, ignore, but record the first byte if key is sign key
				if(privKey == signKeyPrivate) {
					signKeyFirstModulusByte = buf[OFFSET_CDATA];
				}
			break;
			case (byte)0x82: // Exponent, ignore
				break;
			case (byte)0x83:
				privKey.setP(buf, OFFSET_CDATA, lc);
			break;
			case (byte)0x84:
				privKey.setQ(buf, OFFSET_CDATA, lc);
			break;
			case (byte)0x85:
				privKey.setDP1(buf, OFFSET_CDATA, lc);
			break;
			case (byte)0x86:
				privKey.setDQ1(buf, OFFSET_CDATA, lc);
			break;
			case (byte)0x87:
				privKey.setPQ(buf, OFFSET_CDATA, lc);
			break;
			default:
			}
		}catch(Exception e){
			ISOException.throwIt(SW_WRONG_DATA);
		}
	}

	private short unsigned(byte b) {
		return (short) (b & 0x00FF);
	}

	/** Pads the input according to the RSASSA-PSS algorithm, the result is placed in
	 *  output. The input should be 20-byte SHA1 hash of the message to be signed.
	 *  This method *does not* do signing (encrypting) itself. Due to the randomness
	 *  of this algorithm the subsequent signing may fail (when the result of this method
	 *  is larger than the key modulus) in which case the padding should be attempted again.
	 */
	private void pssPad(byte[] input, short inOffset, short hashLen,

			byte[] output, short outputOffset, short emLen, byte firstKeyByte) throws CryptoException {
		do {
			short hLen = hashLen;
			short outOffset = outputOffset;
			if(hLen != SHA1_LEN || (short)(inOffset + hLen) > input.length || (short)(outOffset + emLen) > output.length) {
				CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
			}
			short sLen = SHA1_LEN;
			short psLen = (short)(emLen - sLen - hLen - 2);
			Util.arrayFillNonAtomic(output, outOffset, emLen, (byte)0x00);
			md.update(output, outOffset, (short)8);
			md.update(input, inOffset, hLen);
			rd.generateData(output, (short)(outOffset + psLen + 1), sLen);
			md.doFinal(output, (short)(outOffset+ psLen + 1), sLen, tmp, TMP_HASH_OFFSET);

			output[(short)(outOffset + psLen)] = (byte)0x01;
			Util.arrayFillNonAtomic(output, outOffset, psLen, (byte)0x00);

			short hOffset = (short)(outOffset + emLen - hLen - 1);
			Util.arrayCopyNonAtomic(tmp, TMP_HASH_OFFSET, output, hOffset, hLen);
			output[(short)(outOffset + emLen - 1)] = (byte)0xbc;
			tmp[(short)(TMP_C_OFFSET+C_LEN-1)] = 0;
			while(outOffset < hOffset) {
				md.update(output, hOffset, hLen);
				md.doFinal(tmp, TMP_C_OFFSET, C_LEN, tmp, TMP_HASH_OFFSET);
				if((short)(outOffset + hLen) > hOffset) {
					hLen = (short)(hOffset - outOffset);
				}
				for(short i = 0; i<hLen; i++) {
					output[outOffset++] ^= tmp[(short)(TMP_HASH_OFFSET + i)];
				}
				tmp[(short)(TMP_C_OFFSET+C_LEN-1)]++;
			}
		}while(firstKeyByte <= tmp[TMP_OFFSET]);
	}

	/**
	 * Encapsulates the file system for the PKI applet.
	 * 
	 * @author Wojciech Mostowski <woj@cs.ru.nl>
	 * 
	 */
	final class FileSystem {

		final static short MASTER_FILE_ID = (short) 0x3F00;

		final static byte PERM_FREE = 0;

		final static byte PERM_PIN = 1;

		private static final byte DIR = -1;

		private Object[] efFiles = null;

		private byte[] efPerms = null;

		private short totalFiles = 0;

		/** Stores the file structure information for this file system.
		 * The initial contents of this array should be following the pattern below,
		 * see also the documentation in the pkihostapi library, the PKIPersoService class.
		 *
		 * The hierarchical structure for the file system in our
		 * applet. The data is as follows, concatenated in sequence:
		 * 
		 * byte 0: -1/0 -1 for DF, 0 for EF
		 * byte 1, 2: fid msb, fid lsb
		 * byte 3: index to the parent in this array, -1 of root node
		 * byte 4: for EF the SFI of this file
		 *         for DF number of children nodes, the list of indexes to the
		 *         children follow.
		 * 
		 * When EF files are created the first byte (initially 0) of the
		 * according file in this structure is replaced with the index to
		 * the {@link #efFiles}, where the reference to the file array
		 * is stored.
		 */
		byte[] fileStructure = null;

		private short[] fileStructureIndex;

		FileNotFoundException fnfe;

		/**
		 * Create a new file system for maxFiles maximum number of files.
		 * 
		 * @param maxFiles
		 *            the maximum number of files.
		 */
		FileSystem(short maxFiles) {
			efFiles = new Object[maxFiles];
			efPerms = new byte[maxFiles];
			fileStructureIndex = JCSystem.makeTransientShortArray((short) 1,
					JCSystem.CLEAR_ON_DESELECT);
			fnfe = new FileNotFoundException();
		}

		/**
		 * Create a new file
		 * 
		 * @param fid
		 *            the ID of the file to be create
		 * @param length
		 *            the file contents length
		 * @param perm
		 *            the permission byte, see {@link #PERM_FREE},
		 *            {@link #PERM_PIN}
		 * @return whether the file was successfully created
		 */
		boolean createFile(short fid, short length, byte perm) {
			if (totalFiles == efFiles.length) {
				return false;
			}
			try {
				short index = searchId((short) 0, fid);
				efFiles[totalFiles] = new byte[length];
				efPerms[totalFiles] = perm;
				fileStructure[index] = (byte) totalFiles;
				totalFiles++;
				return true;
			} catch (FileNotFoundException e) {
				return false;
			}
		}

		/**
		 * Returns the array with the contents of the given file
		 * 
		 * @param index
		 *            the index to the file
		 * @return the array with the contents of the file
		 */
		byte[] getFile(short index) {
			try {
				return (byte[]) efFiles[index];
			} catch (ArrayIndexOutOfBoundsException aioobe) {
				return null;
			}
		}

		/**
		 * Returns the permission byte of the given file
		 * 
		 * @param index
		 *            the index to the file
		 * @return the permission byte of the file
		 */
		byte getPerm(short index) {
			return efPerms[index];
		}

		/**
		 * Get the index to the currently selected file, -1 if none selected.
		 * 
		 * @return the index to the currently selected file
		 */
		short getCurrentIndex() {
			short index = (short) (fileStructureIndex[0] - 1);
			if (index == -1) {
				return -1;
			}
			return fileStructure[index];
		}

		/**
		 * Selects the file by the file identifier - global search from the root.
		 * 
		 * @param id
		 *            id of the file to be selected
		 * @return whether selection was successful
		 */
		boolean selectEntryAbsolute(short id) {
			try {
				fileStructureIndex[0] = (short) (searchId((short) 0, id) + 1);
				return true;
			} catch (FileNotFoundException fnfe) {
				return false;
			}
		}

		/**
		 * Select the parent file of the currently selected file, if possible.
		 * 
		 * @return whether selection was successful
		 */
		boolean selectEntryParent() {
			try {
				short index = (short) (fileStructureIndex[0] - 1);
				if (index == -1 || fileStructure[index] != DIR) {
					return false;
				}
				index = fileStructure[(short) (index + 1)];
				if (index == -1) {
					return false;
				}
				fileStructureIndex[0] = (short) (index + 1);
				return true;
			} catch (ArrayIndexOutOfBoundsException aioobe) {
				return false;
			}
		}

		/**
		 * Select the EF or DF file under the currently selected file.
		 * 
		 * @param id
		 *            the id of the file to be selected
		 * @param ef
		 *            whether the file to be selected is EF or DF
		 * @return whether selection was successful
		 */
		boolean selectEntryUnderCurrent(short id, boolean ef) {
			short index = (short) (fileStructureIndex[0] - 1);
			if (index == -1) {
				return false;
			}
			try {
				index = findEntryRelative(index, id);
				if ((fileStructure[index] != DIR) == ef) {
					fileStructureIndex[0] = (short) (index + 1);
					return true;
				}
			} catch (FileNotFoundException fnfe) {
			}
			return false;
		}

		/**
		 * Select the file by path.
		 * 
		 * @param path
		 *            the array with the path data
		 * @param offset
		 *            offset to that array
		 * @param length
		 *            the length of the path
		 * @param master
		 *            if true the path is from the root, otherwise from the
		 *            currently selected file
		 * @return whether selection was successful
		 */
		boolean selectEntryByPath(byte[] path, short offset, short length,
				boolean master) {
			short index = master ? 0 : (short) (fileStructureIndex[0] - 1);
			if (index == -1) {
				return false;
			}
			try {
				index = findEntryPath(index, path, offset, length);
				fileStructureIndex[0] = (short) (index + 1);
				return true;
			} catch (FileNotFoundException fnfe) {
				return false;
			}
		}

		/**
		 * Find the index the file specified by SFI under the current (if exists) DF
		 * file
		 * 
		 * @param sfi
		 *            the SFI of the file to find the index for
		 * @return the index to the file, -1 if not found
		 */
		short findCurrentSFI(byte sfi) {
			try {
				short start = (short) (fileStructureIndex[0] - 1);
				if (start == -1 || fileStructure[start] != DIR) {
					return -1;
				}
				short childNum = fileStructure[(short) (start + 4)];
				for (short i = 0; i < childNum; i++) {
					short index = fileStructure[(short) (start + (short) (i + 5))];
					if (fileStructure[index] != DIR) {
						if (fileStructure[(short) (index + 4)] == sfi)
							return index;
					}
				}
			} catch (ArrayIndexOutOfBoundsException aioobe) {

			}
			return -1;
		}

		private short findEntryRelative(short start, short id)
				throws FileNotFoundException {
			try {
				if (fileStructure[start] != DIR) {
					throw fnfe;
				}
				short childNum = fileStructure[(short) (start + 4)];

				for (short i = 0; i < childNum; i++) {
					short index = fileStructure[(short) (start + (short) (5 + i))];
					short fid = Util.getShort(fileStructure, (short) (index + 1));
					if (fid == id) {
						return index;
					}
				}
			} catch (ArrayIndexOutOfBoundsException aioobe) {

			}
			throw fnfe;
		}

		private short findEntryPath(short start, byte[] path, short offset,
				short length) throws FileNotFoundException {
			try {
				if (length == 0) {
					return start;
				}
				short id = Util.makeShort(path[offset], path[(short) (offset + 1)]);
				start = findEntryRelative(start, id);
				offset += 2;
				length = (short) (length - 2);
				return findEntryPath(start, path, offset, length);
			} catch (ArrayIndexOutOfBoundsException aioobe) {
				throw fnfe;
			}
		}

		/**
		 * Searches for an index to the file specified by the id in the file
		 * structure starting from position start.
		 * 
		 * @param start
		 *            starting position to search
		 * @param id
		 *            the id of the file that is searched
		 * @return the index of the file, if found
		 * @throws FileNotFoundException
		 *             when file not found
		 */
		short searchId(short start, short id) throws FileNotFoundException {
			return searchId(this.fileStructure, (short) 0, start,
					(short) this.fileStructure.length, id);
		}

		/**
		 * Searches for an index to the file specified by the id in the file
		 * structure starting from position start.
		 * 
		 * @param fileStructureArray
		 *            the array with the file structure
		 * @param shift
		 *            the shift in the input array (e.g. when the array is the APDU
		 *            with the header bytes)
		 * @param start
		 *            starting position to search
		 * @param lastOffset
		 *            the last valid offset in the input array
		 * @param id
		 *            the id of the file that is searched
		 * @return the index of the file, if found
		 * @throws ArrayIndexOutOfBoundsException
		 *             when start and lastOffset point outside of the input array
		 * @throws FileNotFoundException
		 *             when file not found
		 */
		short searchId(byte[] fileStructureArray, short shift, short start,
				short lastOffset, short id) throws ArrayIndexOutOfBoundsException,
				FileNotFoundException {
			if (start < 0 || start > (short) (lastOffset - 5)) {
				// This sould produce ArrayIndexOutOfBoundsException
				fileStructureArray[fileStructureArray.length] = (byte) 0xFF;
			}
			short fid = Util.getShort(fileStructureArray, (short) (start + 1));
			if (fid == id) {
				return start;
			}
			if (fileStructureArray[start] != DIR) {
				throw fnfe;
			} else {
				short childNum = fileStructureArray[(short) (start + 4)];
				if (start > (short) ((short) (lastOffset - 5) - childNum)) {
					fileStructureArray[fileStructureArray.length] = (byte) 0xFF;
				}
				for (short i = 0; i < childNum; i++) {
					try {
						return searchId(
								fileStructureArray,
								shift,
								(short) (fileStructureArray[(short) (start + (short) (5 + i))] + shift),
								lastOffset, id);
					} catch (FileNotFoundException e) {
					}
				}
			}
			throw fnfe;
		}
	}


	/**
	 * Tagging class for file not found exceptions.
	 * 
	 * @author Wojciech Mostowski <woj@cs.ru.nl>
	 * 
	 */
	private static final class FileNotFoundException extends Exception {
	}

}
