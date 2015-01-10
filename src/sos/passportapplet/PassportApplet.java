/*
 * passportapplet - A reference implementation of the MRTD standards.
 *
 * Copyright (C) 2006  SoS group, Radboud University
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
 * $Id: PassportApplet.java 945 2009-05-12 08:31:57Z woj76 $
 */

package sos.passportapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

// API for setATRHistBytes - requires Global Platform API gp211.jar
// Comment out the following line if API not available.
// import org.globalplatform.GPSystem;

/**
 * PassportApplet
 * 
 * @author ceesb (ceeesb@gmail.com)
 * @author woj (woj@cs.ru.nl)
 * @author martijno (martijn.oostdijk@gmail.com)
 * 
 * @version $Revision: 945 $
 */
public class PassportApplet extends Applet implements ISO7816 {
    static byte volatileState[];

    static byte persistentState;

    /* values for volatile state */
    static final byte CHALLENGED = 1;

    static final byte MUTUAL_AUTHENTICATED = 2; // ie BAC

    static final byte FILE_SELECTED = 4;

    static final byte CHIP_AUTHENTICATED = 0x10;

    static final byte TERMINAL_AUTHENTICATED = 0x20;

    /* values for persistent state */
    static final byte HAS_MUTUALAUTHENTICATION_KEYS = 1;

    static final byte HAS_EXPONENT = 2;

    static final byte LOCKED = 4;

    static final byte HAS_MODULUS = 8;

    static final byte HAS_EC_KEY = 0x10;

    static final byte HAS_CVCERTIFICATE = 0x20;

    static final byte CHAIN_CLA = 0x10;

    /* for authentication */
    static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;

    static final byte INS_GET_CHALLENGE = (byte) 0x84;

    static final byte CLA_PROTECTED_APDU = 0x0c;

    static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;

    /* for EAC */
    static final byte INS_PSO = (byte) 0x2A;

    static final byte INS_MSE = (byte) 0x22;

    static final byte P2_VERIFYCERT = (byte) 0xBE;

    static final byte P1_SETFORCOMPUTATION = (byte) 0x41;

    static final byte P1_SETFORVERIFICATION = (byte) 0x81;

    static final byte P2_KAT = (byte) 0xA6;

    static final byte P2_DST = (byte) 0xB6;

    static final byte P2_AT = (byte) 0xA4;

    /* for reading */
    static final byte INS_SELECT_FILE = (byte) 0xA4;

    static final byte INS_READ_BINARY = (byte) 0xB0;

    /* for writing */
    static final byte INS_UPDATE_BINARY = (byte) 0xd6;

    static final byte INS_CREATE_FILE = (byte) 0xe0;

    static final byte INS_PUT_DATA = (byte) 0xda;

    static final short KEY_LENGTH = 16;

    static final short KEYMATERIAL_LENGTH = 16;

    static final short RND_LENGTH = 8;

    static final short MAC_LENGTH = 8;

    private static final byte PRIVMODULUS_TAG = 0x60;

    private static final byte PRIVEXPONENT_TAG = 0x61;

    private static final byte MRZ_TAG = 0x62;

    private static final byte ECPRIVATEKEY_TAG = 0x63;

    private static final byte CVCERTIFICATE_TAG = 0x64;

    /* status words */
    private static final short SW_OK = (short) 0x9000;

    private static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;

    static final short SW_INTERNAL_ERROR = (short) 0x6d66;

    private byte[] rnd;

    private byte[] ssc;

    private byte[] documentNumber;

    private FileSystem fileSystem;

    private RandomData randomData;

    private short selectedFile;

    private PassportCrypto crypto;

    private PassportInit init;

    static CVCertificate certificate;

    KeyStore keyStore;

    private byte[] lastINS;

    private short[] chainingOffset;

    private byte[] chainingTmp;

    // This is as long we suspect a card verifiable certifcate could be
    private static final short CHAINING_BUFFER_LENGTH = 400;

    // public ATRGlobal atrGlobal;

    /**
     * Creates a new passport applet.
     */
    public PassportApplet(byte mode) {

        fileSystem = new FileSystem();

        randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);

        certificate = new CVCertificate();

        keyStore = new KeyStore(mode);
        switch (mode) {
        case PassportCrypto.CREF_MODE:
            crypto = new CREFPassportCrypto(keyStore);
            break;
        case PassportCrypto.PERFECTWORLD_MODE:
            crypto = new PassportCrypto(keyStore);
            break;
        case PassportCrypto.JCOP41_MODE:
            crypto = new JCOP41PassportCrypto(keyStore);
            break;
        }
        init = new PassportInit(crypto);

        rnd = JCSystem.makeTransientByteArray(RND_LENGTH,
                JCSystem.CLEAR_ON_RESET);
        ssc = JCSystem
                .makeTransientByteArray((byte) 8, JCSystem.CLEAR_ON_RESET);
        volatileState = JCSystem.makeTransientByteArray((byte) 1,
                JCSystem.CLEAR_ON_RESET);
        lastINS = JCSystem.makeTransientByteArray((short) 1,
                JCSystem.CLEAR_ON_DESELECT);
        chainingOffset = JCSystem.makeTransientShortArray((short) 1,
                JCSystem.CLEAR_ON_DESELECT);
        chainingTmp = JCSystem.makeTransientByteArray(CHAINING_BUFFER_LENGTH,
                JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Installs an instance of the applet. The default crypto mode is now
     * PERFECTWORLD_MODE as the new JCOP41 cards support all required crypto.
     * 
     * @param buffer
     * @param offset
     * @param length
     * @see javacard.framework.Applet#install(byte[], byte, byte)
     */
    public static void install(byte[] buffer, short offset, byte length) {
        (new PassportApplet(PassportCrypto.JCOP41_MODE)).register();
    }

    /**
     * Processes incoming APDUs.
     * 
     * @param apdu
     * @see javacard.framework.Applet#process(javacard.framework.APDU)
     */
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[OFFSET_CLA];
        byte ins = buffer[OFFSET_INS];
        short sw1sw2 = SW_OK;
        boolean protectedApdu = (byte)(cla & CLA_PROTECTED_APDU)  == CLA_PROTECTED_APDU;
        short responseLength = 0;
        short le = 0;

        if (lastINS[0] != ins) {
            chainingOffset[0] = 0;
        }
        lastINS[0] = ins;

        /* Ignore APDU that selects this applet... */
        if (selectingApplet()) {
            // Set ATR Historical Bytes (ATS).
            // Requires gp211 API. Comment out the following line if API not
            // available.
            // org.globalplatform.GPSystem.setATRHistBytes(ATRGlobal.ATR_HIST,
            // (short) 0x00, ATRGlobal.ATR_HIST_LEN);
            return;
        }

        if (protectedApdu & hasMutuallyAuthenticated()) {
            try {
                le = crypto.unwrapCommandAPDU(ssc, apdu);
            } catch (CardRuntimeException e) {
                sw1sw2 = e.getReason();
            }
        } else if (protectedApdu) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        if (sw1sw2 == SW_OK) {
            try {
                responseLength = processAPDU(apdu, cla, ins, protectedApdu, le);
            } catch (CardRuntimeException e) {
                sw1sw2 = e.getReason();
            }
        }

        if (protectedApdu && hasMutuallyAuthenticated()) {
            responseLength = crypto.wrapResponseAPDU(ssc, apdu, crypto
                    .getApduBufferOffset(responseLength), responseLength,
                    sw1sw2);
        }

        if (responseLength > 0) {
            if (apdu.getCurrentState() != APDU.STATE_OUTGOING)
                apdu.setOutgoing();
            if (apdu.getCurrentState() != APDU.STATE_OUTGOING_LENGTH_KNOWN)
                apdu.setOutgoingLength(responseLength);
            apdu.sendBytes((short) 0, responseLength);
        }

        if (sw1sw2 != SW_OK) {
            ISOException.throwIt(sw1sw2);
        }
    }

    /**
      * Processes incoming APDUs, excluding Secure Messaging.
      *
      * This method assumes SM protection has been removed from the
      * incoming APDU, and does not add SM protection to the response.
      * Handling of Secure Messaging is done in process(APDU apdu)
      *
      * @param protectedApdu true if Secure Messaging is used
      * @return length of the response APDU
     */
    public short processAPDU(APDU apdu, byte cla, byte ins,
            boolean protectedApdu, short le) {
        short responseLength = 0;

        switch (ins) {
        case INS_GET_CHALLENGE:
            responseLength = processGetChallenge(apdu, protectedApdu, le);
            break;
        case INS_EXTERNAL_AUTHENTICATE:
            responseLength = processMutualAuthenticate(apdu, protectedApdu);
            break;
        case INS_PSO:
            if (!protectedApdu) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            responseLength = processPSO(apdu);
            break;
        case INS_MSE:
            if (!protectedApdu) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            responseLength = processMSE(apdu);
            break;
        case INS_INTERNAL_AUTHENTICATE:
            responseLength = processInternalAuthenticate(apdu, protectedApdu);
            break;
        case INS_SELECT_FILE:
            processSelectFile(apdu);
            break;
        case INS_READ_BINARY:
            responseLength = processReadBinary(apdu, le, protectedApdu);
            break;
        case INS_UPDATE_BINARY:
            processUpdateBinary(apdu);
            break;
        case INS_CREATE_FILE:
            processCreateFile(apdu);
            break;
        case INS_PUT_DATA:
            processPutData(apdu);
            break;
        default:
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            break;
        }
        return responseLength;
    }

    private short processPSO(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (!hasChipAuthenticated() || hasTerminalAuthenticated()) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (buffer[OFFSET_P1] != (byte) 0x00
                && buffer[OFFSET_P2] != P2_VERIFYCERT) {
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }
        if (certificate.currentCertSubjectId[0] == 0) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        short lc = (short) (buffer[OFFSET_LC] & 0xFF);
        if (chainingOffset[0] > (short) (CHAINING_BUFFER_LENGTH - lc)) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        chainingOffset[0] = Util.arrayCopyNonAtomic(buffer, OFFSET_CDATA,
                chainingTmp, chainingOffset[0], lc);
        if (((byte) (buffer[OFFSET_CLA] & CHAIN_CLA) == CHAIN_CLA)) {
            return (short) 0;
        }
        short chainingTmpLength = chainingOffset[0];
        chainingOffset[0] = (short) 0;

        certificate.parseCertificate(chainingTmp, (short) 0, chainingTmpLength,
                false);
        if (!certificate.verify()) {
            ISOException.throwIt((short) 0x6300);
        }
        return (short) 0;
    }

    private short processMSE(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = (byte) (buffer[OFFSET_P1] & 0xff);
        byte p2 = (byte) (buffer[OFFSET_P2] & 0xff);
        short lc = (short) (buffer[OFFSET_LC] & 0xff);
        short buffer_p = OFFSET_CDATA;

        if (!hasEACKey() || !hasEACCertificate()) {
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
        if (!hasMutuallyAuthenticated() || hasTerminalAuthenticated()) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (p1 == P1_SETFORCOMPUTATION && p2 == P2_KAT) {

            short lastOffset = (short) (lc + OFFSET_CDATA);
            if (buffer_p > (short) (lastOffset - 2)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            if (buffer[buffer_p++] != (byte) 0x91) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            short pubKeyLen = (short) (buffer[buffer_p++] & 0xFF);
            short pubKeyOffset = buffer_p;
            if (pubKeyOffset > (short) (lastOffset - pubKeyLen)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            buffer_p += pubKeyLen;
            short keyIdOffset = 0;
            short keyIdLength = 0;
            if (buffer_p != lastOffset) {
                if (buffer_p > (short) (lastOffset - 2)) {
                    ISOException.throwIt(SW_WRONG_LENGTH);
                }
                if (buffer[buffer_p++] != (byte) 0x84) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                keyIdLength = (short) (buffer[buffer_p++] & 0xFF);
                keyIdOffset = buffer_p;
                if (keyIdOffset != (short) (lastOffset - keyIdLength)) {
                    ISOException.throwIt(SW_WRONG_LENGTH);
                }
                // ignore the key id, we don't use it for now
            }
            if (!crypto.authenticateChip(buffer, pubKeyOffset, pubKeyLen)) {
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            }
            volatileState[0] |= CHIP_AUTHENTICATED;
            return 0;
        } else if (p1 == P1_SETFORVERIFICATION && (p2 == P2_DST || p2 == P2_AT)) {
            if (!hasChipAuthenticated() || hasTerminalAuthenticated()) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            short lastOffset = (short) (lc + OFFSET_CDATA);
            if (buffer_p > (short) (lastOffset - 2)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            if (buffer[buffer_p++] != (byte) 0x83) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            short subIdLen = (short) (buffer[buffer_p++] & 0xFF);
            if (buffer_p != (short) (lastOffset - subIdLen)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            if (!certificate.selectSubjectId(buffer, buffer_p, subIdLen)) {
                ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
            }
        } else {
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }
        return 0;
    }

    private void processPutData(APDU apdu) {
        if (isLocked()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short buffer_p = (short) (OFFSET_CDATA & 0xff);
        short lc = (short) (buffer[OFFSET_LC] & 0xff);
        short p1 = (short) (buffer[OFFSET_P1] & 0xff);
        short p2 = (short) (buffer[OFFSET_P2] & 0xff);

        // sanity check
        if (buffer.length < (short) (buffer_p + lc)) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        if (p1 == 0xde && p2 == 0xad) {
            persistentState |= LOCKED;
        } else if (p1 == 0 && p2 == PRIVMODULUS_TAG) {
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p); // tag ==
            // PRIVMODULUS_TAG
            buffer_p = BERTLVScanner.readLength(buffer, buffer_p); // length ==
            // 00
            buffer_p = BERTLVScanner.skipValue();
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p); // tag == 04
            short modOffset = BERTLVScanner.readLength(buffer, buffer_p);
            short modLength = BERTLVScanner.valueLength;

            if (buffer[modOffset] == 0) {
                modLength--;
                modOffset++;
            }

            keyStore.rsaPrivateKey.setModulus(buffer, modOffset, modLength);
            persistentState |= HAS_MODULUS;
        } else if (p1 == 0 && p2 == PRIVEXPONENT_TAG) {
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p); // tag ==
            // PRIVEXP_TAG
            buffer_p = BERTLVScanner.readLength(buffer, buffer_p); // length ==
            // 00
            buffer_p = BERTLVScanner.skipValue();
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p); // tag == 04
            short expOffset = BERTLVScanner.readLength(buffer, buffer_p);
            short expLength = BERTLVScanner.valueLength;

            // leading zero
            if (buffer[expOffset] == 0) {
                expLength--;
                expOffset++;
            }

            keyStore.rsaPrivateKey.setExponent(buffer, expOffset, expLength);
            persistentState |= HAS_EXPONENT;
        } else if (p1 == 0 && p2 == MRZ_TAG) {
            // data is BERTLV object with three objects; docNr, dataOfBirth,
            // dateOfExpiry
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
            buffer_p = BERTLVScanner.readLength(buffer, buffer_p);
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
            short docNrOffset = BERTLVScanner.readLength(buffer, buffer_p);
            short docNrLength = BERTLVScanner.valueLength;
            buffer_p = BERTLVScanner.skipValue();
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
            short dobOffset = BERTLVScanner.readLength(buffer, buffer_p);
            short dobLength = BERTLVScanner.valueLength;
            buffer_p = BERTLVScanner.skipValue();
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
            short doeOffset = BERTLVScanner.readLength(buffer, buffer_p);
            short doeLength = BERTLVScanner.valueLength;
            buffer_p = BERTLVScanner.skipValue();

            documentNumber = new byte[(short)(docNrLength+1)];
            Util.arrayCopyNonAtomic(buffer, docNrOffset, documentNumber,
                    (short) 0, docNrLength);
            documentNumber[docNrLength] = PassportInit.checkDigit(documentNumber,(short)0, docNrLength);

            short keySeed_offset = init.computeKeySeed(buffer, docNrOffset,
                    docNrLength, dobOffset, dobLength, doeOffset, doeLength);

            short macKey_p = (short) (keySeed_offset + KEYMATERIAL_LENGTH);
            short encKey_p = (short) (keySeed_offset + KEYMATERIAL_LENGTH + KEY_LENGTH);
            crypto.deriveKey(buffer, keySeed_offset, KEYMATERIAL_LENGTH, PassportCrypto.MAC_MODE,
                    macKey_p);
            crypto.deriveKey(buffer, keySeed_offset, KEYMATERIAL_LENGTH, PassportCrypto.ENC_MODE,
                    encKey_p);
            keyStore.setMutualAuthenticationKeys(buffer, macKey_p, buffer,
                    encKey_p);
            persistentState |= HAS_MUTUALAUTHENTICATION_KEYS;
        } else if (p1 == 0 && p2 == ECPRIVATEKEY_TAG) {
            short finish = (short) (buffer_p + lc);
            while (buffer_p < finish) {
                buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
                buffer_p = BERTLVScanner.readLength(buffer, buffer_p);
                short len = BERTLVScanner.valueLength;
                switch (BERTLVScanner.tag) {
                case (short) 0x81:
                    if (len == (short) 6) {
                        short e1 = Util.getShort(buffer, buffer_p);
                        short e2 = Util
                                .getShort(buffer, (short) (buffer_p + 2));
                        short e3 = Util
                                .getShort(buffer, (short) (buffer_p + 4));
                        keyStore.ecPrivateKey.setFieldF2M(e1, e2, e3);
                        keyStore.ecPublicKey.setFieldF2M(e1, e2, e3);
                    } else {
                        keyStore.ecPrivateKey.setFieldF2M(Util.getShort(buffer,
                                buffer_p));
                        keyStore.ecPublicKey.setFieldF2M(Util.getShort(buffer,
                                buffer_p));
                    }
                    break;
                case (short) 0x82:
                    keyStore.ecPrivateKey.setA(buffer, buffer_p, len);
                    keyStore.ecPublicKey.setA(buffer, buffer_p, len);
                    break;
                case (short) 0x83:
                    keyStore.ecPrivateKey.setB(buffer, buffer_p, len);
                    keyStore.ecPublicKey.setB(buffer, buffer_p, len);
                    break;
                case (short) 0x84:
                    keyStore.ecPrivateKey.setG(buffer, buffer_p, len);
                    keyStore.ecPublicKey.setG(buffer, buffer_p, len);
                    break;
                case (short) 0x85:
                    keyStore.ecPrivateKey.setR(buffer, buffer_p, len);
                    keyStore.ecPublicKey.setR(buffer, buffer_p, len);
                    break;
                case (short) 0x86:
                    if (len == (short) 20) {
                        buffer_p--;
                        len++;
                        buffer[buffer_p] = 0x00;
                    }
                    keyStore.ecPrivateKey.setS(buffer, buffer_p, len);
                    break;
                case (short) 0x87:
                    // This is the k, ignore it
                    // short k = Util.getShort(buffer, buffer_p);
                    break;
                default:
                    ISOException.throwIt(SW_WRONG_DATA);
                break;
            }
            buffer_p = BERTLVScanner.skipValue();
        }
        if (keyStore.ecPrivateKey.isInitialized()) {
            persistentState |= HAS_EC_KEY;
        } else {
            ISOException.throwIt(SW_WRONG_DATA);
        }
    } else if (p2 == CVCERTIFICATE_TAG) {
        if ((byte) (persistentState & HAS_CVCERTIFICATE) == HAS_CVCERTIFICATE) {
            // We already have the certificate initialized
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        certificate.parseCertificate(buffer, buffer_p, lc, true);
        certificate.setRootCertificate(buffer, p1);
        persistentState |= HAS_CVCERTIFICATE;
    } else {
        ISOException.throwIt(SW_INCORRECT_P1P2);
    }
    }

    /**
     * Processes INTERNAL_AUTHENTICATE apdus, ie Active Authentication (AA). 
     * Receives a random and signs it.
     * 
     * @param apdu
     * @param protectedApdu true if Secure Messaging was used
     * @return
     */
    private short processInternalAuthenticate(APDU apdu, boolean protectedApdu) {
        if (!hasInternalAuthenticationKeys() || !hasMutuallyAuthenticated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short buffer_p = (short) (OFFSET_CDATA & 0xff);
        short hdr_offset = 0;
        if (protectedApdu) {
            hdr_offset = crypto.getApduBufferOffset((short) 128);
        }
        short hdr_len = 1;
        short m1_len = 106; // whatever
        short m1_offset = (short) (hdr_offset + hdr_len);
        short m2_len = 8;
        short m2_offset = (short) (m1_offset + m1_len);
        // we will write the hash over m2
        short m1m2hash_offset = (short) (m1_offset + m1_len);
        short m1m2hash_len = 20;
        short trailer_offset = (short) (m1m2hash_offset + m1m2hash_len);
        short trailer_len = 1;

        byte[] buffer = apdu.getBuffer();
        short bytesLeft = (short) (buffer[OFFSET_LC] & 0x00FF);

        if (bytesLeft != m2_len)
            ISOException.throwIt(SW_WRONG_LENGTH);

        // put m2 in place
        Util.arrayCopyNonAtomic(buffer, buffer_p, buffer, m2_offset, m2_len);

        // write some random data of m1_len
        // randomData.generateData(buffer, m1_offset, m1_length);
        for (short i = m1_offset; i < (short) (m1_offset + m1_len); i++) {
            buffer[i] = 0;
        }

        // calculate SHA1 hash over m1 and m2
        crypto.shaDigest.doFinal(buffer, m1_offset, (short) (m1_len + m2_len), buffer,
                m1m2hash_offset);
        crypto.shaDigest.reset();

        // write trailer
        buffer[trailer_offset] = (byte) 0xbc;

        // write header
        buffer[hdr_offset] = (byte) 0x6a;

        // encrypt the whole buffer with our AA private key
        short plaintext_len = (short) (hdr_len + m1_len + m1m2hash_len + trailer_len);
        // sanity check
        if (plaintext_len != 128) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }
        crypto.rsaCiph.init(keyStore.rsaPrivateKey, Cipher.MODE_ENCRYPT);
        short ciphertext_len = crypto.rsaCiph.doFinal(buffer, hdr_offset,
                plaintext_len, buffer, hdr_offset);
        // sanity check
        if (ciphertext_len != 128) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        return ciphertext_len;
    }

    /**
     * Processes incoming GET_CHALLENGE APDUs, as part of BAC or EAC.
     * 
     * Generates random 8 bytes, sends back result and stores result in rnd.
     * A GET_CHALLENGE APDU can be sent as part of BAC, or as part of
     * EAC (more specifically, Terminal Authentication (TA).
     * 
     * @param apdu
     *            is used for sending (8 bytes) only
     * @param protectedApdu true if Secure Messaging was used
     */
    private short processGetChallenge(APDU apdu, boolean protectedApdu, short le) {
        if (protectedApdu) {
            // we're doing TA
            if (!hasChipAuthenticated()
                    || certificate.cert1HolderReference[0] == (byte)0
                    || hasTerminalAuthenticated()) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } else {
            // we're doing BAC
            if (!hasMutualAuthenticationKeys() || hasMutuallyAuthenticated()) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }
        byte[] buffer = apdu.getBuffer();
        if (!protectedApdu) {
            le = apdu.setOutgoing();
        }
        // For the BAP challenge the length should be 8, for the EAP challenge
        // we guess other lenghts are fine too?
        if (le != 8) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        randomData.generateData(rnd, (short) 0, le);
        short bufferOffset = protectedApdu ? crypto.getApduBufferOffset(le)
                : (short) 0;
        Util.arrayCopyNonAtomic(rnd, (short) 0, buffer, bufferOffset, le);

        volatileState[0] |= CHALLENGED;

        return le;
    }

    /**
     * Processes incoming EXTERNAL_AUTHENTICATE APDUs, as part of BAC or EAC.
     *
     * An EXTERNAL_AUTHENTICATE can be the last step of BAC, or the last
     * step of Terminal Authentication (TA) when doing EAC.
     * 
     * @param apdu
     *            the APDU
     * @param protectedApdu true if Secure Messaging was used
     * @return length of response APDU
     */
    private short processMutualAuthenticate(APDU apdu, boolean protectedApdu) {
        if (protectedApdu) {
            // we're doing EAC
            if (!hasChipAuthenticated() || !isChallenged()
                    || certificate.currentCertSubjectId[0] == (byte)0
                    || hasTerminalAuthenticated()) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            byte[] buffer = apdu.getBuffer();
            short buffer_p = OFFSET_CDATA;
            short lc = (short) (buffer[OFFSET_LC] & 0xFF);
            setNoChallenged();
            if (!crypto.eacVerifySignature(certificate.currentCertPublicKey, rnd,
                    documentNumber, buffer, buffer_p, lc)) {
                certificate.clear();
                ISOException.throwIt((short) 0x6300);
            }
            certificate.clear();
            volatileState[0] |= TERMINAL_AUTHENTICATED;
            return 0;
        } else {
        // we're doing BAC
        if (!isChallenged() || hasMutuallyAuthenticated()) {
               ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
           }

        byte[] buffer = apdu.getBuffer();
        short bytesLeft = (short) (buffer[OFFSET_LC] & 0x00FF);
        short e_ifd_length = RND_LENGTH + RND_LENGTH + KEYMATERIAL_LENGTH;

        // incoming message is e_ifd || m_ifd
        // where e_ifd == E_KENC(rnd_ifd || rnd_icc || k_ifd)
        if (bytesLeft != (short) (e_ifd_length + MAC_LENGTH))
            ISOException.throwIt(SW_WRONG_LENGTH);

        short e_ifd_p = OFFSET_CDATA;
        short m_ifd_p = (short) (e_ifd_p + e_ifd_length);

        if (apdu.getCurrentState() == APDU.STATE_INITIAL) {
            apdu.setIncomingAndReceive();
        }
        if (apdu.getCurrentState() != APDU.STATE_FULL_INCOMING) {
            // need all data in one APDU.
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        // buffer[OFFSET_CDATA ... +40] consists of e_ifd || m_ifd
        // verify checksum m_ifd of cryptogram e_ifd
        crypto.initMac(Signature.MODE_VERIFY);
        if (!crypto.verifyMacFinal(buffer, e_ifd_p, e_ifd_length, buffer,
                m_ifd_p))
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

        // decrypt e_ifd into buffer[0] where buffer = rnd.ifd || rnd.icc ||
        // k.ifd
        crypto.decryptInit();
        short plaintext_len = crypto.decryptFinal(buffer, e_ifd_p,
                e_ifd_length, buffer, (short) 0);
        if (plaintext_len != e_ifd_length) // sanity check
            ISOException.throwIt(SW_INTERNAL_ERROR);

        short rnd_ifd_p = 0;
        short rnd_icc_p = RND_LENGTH;
        short k_ifd_p = (short) (rnd_icc_p + RND_LENGTH);

        /*
         * we use apdu buffer for writing intermediate data in buffer with
         * following pointers
         */
        short k_icc_p = (short) (k_ifd_p + KEYMATERIAL_LENGTH);
        short keySeed_p = (short) (k_icc_p + KEYMATERIAL_LENGTH);
        short keys_p = (short) (keySeed_p + KEYMATERIAL_LENGTH);

        // verify that rnd.icc equals value generated in getChallenge
        if (Util.arrayCompare(buffer, rnd_icc_p, rnd, (short) 0, RND_LENGTH) != 0)
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

        // generate keying material k.icc
        randomData.generateData(buffer, k_icc_p, KEYMATERIAL_LENGTH);

        // calculate keySeed for session keys by xorring k_ifd and k_icc
        PassportUtil.xor(buffer, k_ifd_p, buffer, k_icc_p, buffer, keySeed_p,
                KEYMATERIAL_LENGTH);

        // calculate session keys
        crypto.deriveKey(buffer, keySeed_p, KEYMATERIAL_LENGTH, PassportCrypto.MAC_MODE, keys_p);
        short macKey_p = keys_p;
        keys_p += KEY_LENGTH;
        crypto.deriveKey(buffer, keySeed_p, KEYMATERIAL_LENGTH, PassportCrypto.ENC_MODE, keys_p);
        short encKey_p = keys_p;
        keys_p += KEY_LENGTH;
        keyStore.setSecureMessagingKeys(buffer, macKey_p, buffer, encKey_p);

        // compute ssc
        PassportCrypto.computeSSC(buffer, rnd_icc_p, buffer, rnd_ifd_p, ssc);

        // create response in buffer where response = rnd.icc || rnd.ifd ||
        // k.icc
        PassportUtil.swap(buffer, rnd_icc_p, rnd_ifd_p, RND_LENGTH);
        Util.arrayCopyNonAtomic(buffer, k_icc_p, buffer, (short) (2 * RND_LENGTH),
                KEYMATERIAL_LENGTH);

        // make buffer encrypted using k_enc
        crypto.encryptInit();
        short ciphertext_len = crypto.encryptFinal(buffer, (short) 0,
                (short) (2 * RND_LENGTH + KEYMATERIAL_LENGTH), buffer,
                (short) 0);

        // create m_icc which is a checksum of response
        crypto.initMac(Signature.MODE_SIGN);
        crypto.createMacFinal(buffer, (short) 0, ciphertext_len, buffer,
                ciphertext_len);

        setNoChallenged();
        volatileState[0] |= MUTUAL_AUTHENTICATED;

        return (short) (ciphertext_len + MAC_LENGTH);
        
        }
    }

    /**
     * Processes incoming SELECT_FILE APDUs.
     * 
     * @param apdu
     *            where the first 2 data bytes encode the file to select.
     */
    private void processSelectFile(APDU apdu) {
        if (isLocked() & !hasMutuallyAuthenticated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short lc = (short) (buffer[OFFSET_LC] & 0x00FF);

        if (lc != 2)
            ISOException.throwIt(SW_WRONG_LENGTH);

        if (apdu.getCurrentState() == APDU.STATE_INITIAL) {
            apdu.setIncomingAndReceive();
        }
        if (apdu.getCurrentState() != APDU.STATE_FULL_INCOMING) {
            // need all data in one APDU.
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        short fid = Util.getShort(buffer, OFFSET_CDATA);

        if (fileSystem.getFile(fid) != null) {
            selectedFile = fid;
            volatileState[0] |= FILE_SELECTED;
            return;
        }
        setNoFileSelected();
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    /**
     * Processes incoming READ_BINARY APDUs. Returns data of the currently
     * selected file.
     * 
     * @param apdu
     *            where the offset is carried in header bytes p1 and p2.
     * @param le
     *            expected length by terminal
     * @return length of the response APDU
     */
    private short processReadBinary(APDU apdu, short le, boolean protectedApdu) {
        if (!hasMutuallyAuthenticated()) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (!hasFileSelected()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[OFFSET_P1];
        byte p2 = buffer[OFFSET_P2];

        short offset = Util.makeShort(p1, p2);

        byte[] file = fileSystem.getFile(selectedFile);
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        short len;
        short fileSize = fileSystem.getFileSize(selectedFile);

        len = PassportUtil.min((short) (buffer.length - 37),
                (short) (fileSize - offset));
        // FIXME: 37 magic
        len = PassportUtil.min(len, (short) buffer.length);
        len = PassportUtil.min(le, len);
        short bufferOffset = 0;
        if (protectedApdu) {
            bufferOffset = crypto.getApduBufferOffset(len);
        }
        Util.arrayCopyNonAtomic(file, offset, buffer, bufferOffset, len);

        return len;
    }

    /**
     * Processes and UPDATE_BINARY apdu. Writes data in the currently selected
     * file.
     * 
     * @param apdu
     *            carries the offset where to write date in header bytes p1 and
     *            p2.
     */
    private void processUpdateBinary(APDU apdu) {
        if (!hasFileSelected() || isLocked()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[OFFSET_P1];
        byte p2 = buffer[OFFSET_P2];
        short offset = Util.makeShort(p1, p2);

        short readCount = (short) (buffer[ISO7816.OFFSET_LC] & 0xff);
        readCount = apdu.setIncomingAndReceive();

        while (readCount > 0) {
            fileSystem.writeData(selectedFile, offset, buffer, OFFSET_CDATA,
                    readCount);
            offset += readCount;
            readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
    }

    /**
     * Processes and CREATE_FILE apdu.
     * 
     * This functionality is only partly implemented. Only non-directories
     * (files) can be created, all options for CREATE_FILE are ignored.
     * 
     * @param apdu
     *            containing 6 bytes: 0x64 || (1 byte) || size (2) || fid (2)
     */
    private void processCreateFile(APDU apdu) {
        if (isLocked()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short lc = (short) (buffer[OFFSET_LC] & 0xff);

        if (apdu.getCurrentState() == APDU.STATE_INITIAL) {
            apdu.setIncomingAndReceive();
        }
        if (apdu.getCurrentState() != APDU.STATE_FULL_INCOMING) {
            // need all data in one APDU.
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        if (lc < (short) 6 || (buffer[OFFSET_CDATA + 1] & 0xff) < 4)
            ISOException.throwIt(SW_WRONG_LENGTH);

        if (buffer[OFFSET_CDATA] != 0x63)
            ISOException.throwIt(SW_DATA_INVALID);

        short size = Util.makeShort(buffer[(short) (OFFSET_CDATA + 2)],
                buffer[(short) (OFFSET_CDATA + 3)]);

        short fid = Util.makeShort(buffer[(short) (OFFSET_CDATA + 4)],
                buffer[(short) (OFFSET_CDATA + 5)]);

        if(fid == FileSystem.EF_CVCA_FID) {
           fileSystem.createFile(fid, size, certificate);
        }else{
           fileSystem.createFile(fid, size);
        }
    }

    public static boolean hasInternalAuthenticationKeys() {
        return (persistentState & (HAS_EXPONENT | HAS_MODULUS)) == (HAS_EXPONENT | HAS_MODULUS);
    }

    public static boolean hasMutualAuthenticationKeys() {
        return (persistentState & HAS_MUTUALAUTHENTICATION_KEYS) == HAS_MUTUALAUTHENTICATION_KEYS;
    }

    public static boolean hasEACKey() {
        return (persistentState & HAS_EC_KEY) == HAS_EC_KEY;
    }

    public static boolean hasEACCertificate() {
        return (persistentState & HAS_CVCERTIFICATE) == HAS_CVCERTIFICATE;
    }

    public static void setNoFileSelected() {
        if (hasFileSelected()) {
            volatileState[0] ^= FILE_SELECTED;
        }
    }

    public static void setNoChallenged() {
        if ((volatileState[0] & CHALLENGED) == CHALLENGED) {
            volatileState[0] ^= CHALLENGED;
        }
    }

    public static boolean hasFileSelected() {
        return (volatileState[0] & FILE_SELECTED) == FILE_SELECTED;
    }

    public static boolean isLocked() {
        return (persistentState & LOCKED) == LOCKED;
    }

    public static boolean isChallenged() {
        return (volatileState[0] & CHALLENGED) == CHALLENGED;
    }

	/** Has BAC been completed? */
    public static boolean hasMutuallyAuthenticated() {
        return (volatileState[0] & MUTUAL_AUTHENTICATED) == MUTUAL_AUTHENTICATED;
    }
    
    public static boolean hasChipAuthenticated() {
        return (volatileState[0] & CHIP_AUTHENTICATED) == CHIP_AUTHENTICATED;
    }

    public static boolean hasTerminalAuthenticated() {
        return (volatileState[0] & TERMINAL_AUTHENTICATED) == TERMINAL_AUTHENTICATED;
    }

}
