/*
 * GidsApplet: A Java Card implementation of the GIDS (Generic Identity
 * Device Specification) specification
 * https://msdn.microsoft.com/en-us/library/windows/hardware/dn642100%28v=vs.85%29.aspx
 * Copyright (C) 2016  Vincent Le Toux(vincent.letoux@mysmartlogon.com)
 *
 * It has been based on the IsoApplet
 * Copyright (C) 2014  Philip Wendland (wendlandphilip@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

package com.mysmartlogon.gidsApplet;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import javacard.security.CryptoException;

/**
 * \brief The GidsApplet class.
 *
 *
 */
public class GidsApplet extends Applet {
    /* API Version */
    public static final byte API_VERSION_MAJOR = (byte) 0x00;
    public static final byte API_VERSION_MINOR = (byte) 0x06;

    /* Card-specific configuration */
    public static final boolean DEF_PRIVATE_KEY_IMPORT_ALLOWED = true;

    /* ISO constants not in the "ISO7816" interface */
    // File system related INS:
    public static final byte INS_CREATE_FILE = (byte) 0xE0;
    public static final byte INS_UPDATE_BINARY = (byte) 0xD6;
    public static final byte INS_READ_BINARY = (byte) 0xB0;
    public static final byte INS_DELETE_FILE = (byte) 0xE4;
    // Other INS:
    public static final byte INS_VERIFY = (byte) 0x20;
    public static final byte INS_CHANGE_REFERENCE_DATA = (byte) 0x24;
    public static final byte INS_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x47;
    public static final byte INS_RESET_RETRY_COUNTER = (byte) 0x2C;
    public static final byte INS_MANAGE_SECURITY_ENVIRONMENT = (byte) 0x22;
    public static final byte INS_PERFORM_SECURITY_OPERATION = (byte) 0x2A;
    public static final byte INS_GET_RESPONSE = (byte) 0xC0;
    public static final byte INS_PUT_DATA = (byte) 0xDB;
    public static final byte INS_GET_CHALLENGE = (byte) 0x84;
    public static final byte INS_GENERAL_AUTHENTICATE = (byte) 0x87;
    public static final byte INS_GET_DATA = (byte) 0xCB;
    public static final byte INS_ACTIVATE_FILE = (byte) 0x44;
    public static final byte INS_TERMINATE_DF = (byte) 0xE6;

    private GidsPINManager pinManager = null;


    /* Member variables: */
    private GidsFileSystem fs = null;
    private byte[] currentAlgorithmRef;
    private Object[] currentKey;
    private TransmitManager transmitManager = null;
    private Cipher rsaPkcs1Cipher = null;
    private Cipher rsaOaepCipher = null;
    private Cipher rsaRawCipher = null;


    /**
     * \brief Installs this applet.
     *
     * \param bArray
     *			the array containing installation parameters
     * \param bOffset
     *			the starting offset in bArray
     * \param bLength
     *			the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new GidsApplet();
    }

    /**
     * \brief Only this class's install method should create the applet object.
     */
    protected GidsApplet() {

        // by default the pin manager is in "initialization mode"
        pinManager = new GidsPINManager();

        transmitManager = new TransmitManager();

        currentAlgorithmRef = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        currentKey = JCSystem.makeTransientObjectArray((short)1, JCSystem.CLEAR_ON_DESELECT);

        rsaPkcs1Cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        try {
            rsaOaepCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1_OAEP, false);
        } catch (CryptoException e) {
            if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                rsaOaepCipher = null;
            } else {
                throw e;
            }
        }
        rsaRawCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        byte mechanisms =  (byte) 0xC0;
        fs = new GidsFileSystem(pinManager, transmitManager, (short) 0x3F00,
                                // FCP
                                new byte[]	{
                                    (byte)0x62, (byte)0x08,
                                    (byte)0x82, (byte)0x01, (byte)0x38, // File descriptor byte.
                                    (byte)0x8C, (byte)0x03, (byte)0x03, (byte)0x30, (byte)0x30,// security attribute
                                },
                                // FCI
                                new byte[]	{
                                    0x61, 0X12,
                                    0x4F, 0x0B, (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x97, (byte) 0x42, (byte) 0x54, (byte) 0x46, (byte) 0x59, 0x02, 0x01, // AID
                                    0x73, 0x03,
                                    0x40, 0x01, mechanisms, // cryptographic mechanism
                                },
                                // FMD
                                new byte[]	{
                                    (byte)0x64, (byte)0x09,
                                    (byte)0x5F, (byte)0x2F, (byte) 0x01, (byte) 0x60, // pin usage policy
                                    (byte)0x7F, (byte)0x65, 0x02, (byte) 0x80, 0x00
                                }
                               );

        // FCI / FMD / FCP are hard coded
        register();
    }

    /**
     * \brief This method is called whenever the applet is being deselected.
     */
    public void deselect() {
        pinManager.DeauthenticateAllPin();
    }

    /**
     * \brief Processes an incoming APDU.
     *
     * \see APDU.
     *
     * \param apdu The incoming APDU.
     */
    public void process(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        // No secure messaging at the moment
        if((buffer[ISO7816.OFFSET_CLA] & 0x0C) != 0) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        transmitManager.processChainInitialization(apdu);

        if((buffer[ISO7816.OFFSET_CLA] & 0xE0) == 0) {
            switch (ins) {
            case INS_ACTIVATE_FILE:
                fs.processActivateFile(apdu);
                break;
            case INS_CREATE_FILE:
                fs.processCreateFile(apdu);
                break;
            case INS_CHANGE_REFERENCE_DATA:
                pinManager.processChangeReferenceData(apdu);
                break;
            case INS_DELETE_FILE:
                fs.processDeleteFile(apdu);
                break;
            case INS_GENERAL_AUTHENTICATE:
                pinManager.processGeneralAuthenticate(apdu);
                break;
            case INS_GENERATE_ASYMMETRIC_KEYPAIR:
                processGenerateAsymmetricKeypair(apdu);
                break;
            case INS_GET_DATA:
                processGetData(apdu);
                break;
            case INS_GET_RESPONSE:
                transmitManager.processGetResponse(apdu);
                break;
            case INS_MANAGE_SECURITY_ENVIRONMENT:
                processManageSecurityEnvironment(apdu);
                break;
            case INS_PERFORM_SECURITY_OPERATION:
                processPerformSecurityOperation(apdu);
                break;
            case INS_PUT_DATA:
                processPutData(apdu);
                break;
            case INS_RESET_RETRY_COUNTER:
                pinManager.processResetRetryCounter(apdu);
                break;
            case ISO7816.INS_SELECT:
                fs.processSelectFile(apdu, selectingApplet());
                break;
            case INS_TERMINATE_DF:
                processTerminateDF(apdu);
                break;
            case INS_VERIFY:
                pinManager.processVerify(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            } // switch
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }



    private void processTerminateDF(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if (p1 != (byte) 0x00 || p2 != (byte) 0x00 ) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        fs.CheckPermission(pinManager, File.ACL_OP_DF_TERMINATE);
        // kill me
        fs.setState(File.STATE_TERMINATED);
    }

    /**
         * \brief Process the GET DATA apdu (INS = CA)
         *
         * This APDU can be used to request the following data:
         *   P1P2 = 0x1001: Applet version and features
         *
         * \param apdu The apdu to process.
         */
    private void processGetData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;

        if (p1 == 0x3F && p2 == (byte) 0xFF) {
            // get Applet information
            // Bytes received must be Lc.
            lc = apdu.setIncomingAndReceive();
            // check for public key request
            // typically 00 CB 3F FF 0A 70 08 84 01 **81** A5 03 7F 49 80 00 (*keyref*)
            if (lc == (short) 10 && buf[5] == (byte) 0x70) {
                CRTKeyFile file = null;
                byte keyID = buf[9];
                try {
                    file = fs.findKeyCRT(keyID);
                } catch (NotFoundException e) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                file.CheckPermission(pinManager, File.ACL_OP_KEY_GETPUBLICKEY);
                PublicKey pk = file.GetKey().getPublic();

                // Return pubkey. See ISO7816-8 table 3.
                try {
                    sendPublicKey(apdu, pk);
                } catch (InvalidArgumentsException e) {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                } catch (NotEnoughSpaceException e) {
                    ISOException.throwIt(ISO7816.SW_FILE_FULL);
                }
            } else if (lc == (short) 04 && buf[5] == (byte) 0x5C && buf[6] == (byte) 0x02) {
                short id = Util.makeShort(buf[7], buf[8]);
                if (id == (short) 0x7F71 || id == (short) 0x7F72 || id == (short) 0x7F73 ) {
                    pinManager.returnPINStatus(apdu, id);
                } else {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

            } else {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        } else if (p1 == 0x2F && p2 == (byte) 0x01) {
            // EF.ATR
            lc = apdu.setIncomingAndReceive();

            // check for EF.ATR request
            // 00 CB 2F 01 02 5C 00 00
            if (lc == (short) 2 && buf[5] == (byte) 0x5C && buf[6] == (byte) 0x00) {
                // 43 01 F4 47 03 08 01 80 46 0C 4D 79 53 6D 61 72 74 4C 6F 67 6F 6E
                buf[0] = (byte) 0x43;
                buf[1] = (byte) 0x01;
                buf[2] = (byte) 0xF4;
                buf[3] = (byte) 0x47;
                buf[4] = (byte) 0x03;
                buf[5] = (byte) 0x08;
                buf[6] = (byte) 0x01;
                buf[7] = (byte) 0x80;
                buf[8] = (byte) 0x46;
                buf[9] = (byte) 0x0C;
                buf[10] = (byte) 0x4D;
                buf[11] = (byte) 0x79;
                buf[12] = (byte) 0x53;
                buf[13] = (byte) 0x6D;
                buf[14] = (byte) 0x61;
                buf[15] = (byte) 0x72;
                buf[16] = (byte) 0x74;
                buf[17] = (byte) 0x4C;
                buf[18] = (byte) 0x6F;
                buf[19] = (byte) 0x67;
                buf[20] = (byte) 0x6F;
                buf[21] = (byte) 0x6E;
                apdu.setOutgoing();
                apdu.setOutgoingLength((short)22);
                apdu.sendBytes((short) 0, (short) 22);
            } else {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        } else {
            // read BER TLV DO
            fs.processGetData(apdu);
        }

    }


    /**
     * \brief Process the GENERATE ASYMMETRIC KEY PAIR apdu (INS = 46).
     *
     * A MANAGE SECURITY ENVIRONMENT must have succeeded earlier to set parameters for key
     * generation.
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_WRONG_LENGTH, SW_INCORRECT_P1P2, SW_CONDITIONS_NOT_SATISFIED,
     *			SW_SECURITY_STATUS_NOT_SATISFIED.
     */
    public void processGenerateAsymmetricKeypair(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc, pos, len, innerOffset, innerLength;
        byte algID=0, keyID=0;
        CRTKeyFile file = null;
        KeyPair kp = null;

        // Check INS: We only support INS=D6 at the moment.
        if (p1 != (byte) 0x00 || p2 != (byte) 0x00 ) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }


        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();

        // TLV structure consistency check.
        if( ! UtilTLV.isTLVconsistent(buf, ISO7816.OFFSET_CDATA, lc)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // length and length-field of outer FCI tag consistency check.
        try {
            innerLength = UtilTLV.decodeLengthField(buf, (short)(ISO7816.OFFSET_CDATA+1));
            if(innerLength != (short)(lc-1-UtilTLV.getLengthFieldLength(buf, (short)(ISO7816.OFFSET_CDATA+1)))) {
                throw InvalidArgumentsException.getInstance();
            }

            // Let innerOffset point to the first inner TLV entry.
            innerOffset = (short) (ISO7816.OFFSET_CDATA + 1 + UtilTLV.getLengthFieldLength(buf, (short)(ISO7816.OFFSET_CDATA+1)));

            // Now we check for the consistency of the lower level TLV entries.
            if( ! UtilTLV.isTLVconsistent(buf, innerOffset, innerLength) ) {
                throw InvalidArgumentsException.getInstance();
            }
            pos = UtilTLV.findTag(buf, innerOffset, innerLength, (byte) 0x83);
            len = UtilTLV.decodeLengthField(buf, (short)(pos+1));
            if (len != (short) 1) {
                throw InvalidArgumentsException.getInstance();
            }
            keyID = buf[(short)(pos+2)];
            pos = UtilTLV.findTag(buf, innerOffset, innerLength, (byte) 0x80);
            len = UtilTLV.decodeLengthField(buf, (short)(pos+1));
            if (len != (short) 1) {
                throw InvalidArgumentsException.getInstance();
            }
            algID = buf[(short)(pos+2)];
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (NotFoundException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        try {
            file = fs.findKeyCRT(keyID);
        } catch (NotFoundException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        file.CheckPermission(pinManager, File.ACL_OP_KEY_GENERATE_ASYMETRIC);
        try {
            switch(algID) {
            case (byte)0x06:
                kp = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
                break;
            case (byte)0x07:
                kp = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                break;
            }
            kp.genKeyPair();
            
            // special Feitian workaround for A40CR and A22CR cards
            RSAPrivateCrtKey priKey = (RSAPrivateCrtKey) kp.getPrivate();
            short pLen = priKey.getP(buf, (short) 0);
            priKey.setP(buf, (short) 0, pLen);
            short qLen = priKey.getQ(buf, (short) 0);
            priKey.setQ(buf, (short) 0, qLen);
            // end of workaround
            
        } catch(CryptoException e) {
            if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        } catch(SystemException e) {
            if(e.getReason() == SystemException.NO_RESOURCE) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        file.SaveKey(kp);

        // Return pubkey. See ISO7816-8 table 3.
        try {
            sendPublicKey(apdu, kp.getPublic());
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        } catch (NotEnoughSpaceException e) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
    }



    private void sendPublicKey(APDU apdu, PublicKey publicKey) throws InvalidArgumentsException, NotEnoughSpaceException {

        if (publicKey instanceof RSAPublicKey) {
            sendRSAPublicKey(apdu, (RSAPublicKey) publicKey);
        }
    }

    /**
     * \brief Encode a 2048 bit RSAPublicKey according to ISO7816-8 table 3 and send it as a response,
     * using an extended APDU.
     *
     * \see ISO7816-8 table 3.
     *
     * \param apdu The apdu to answer. setOutgoing() must not be called already.
     *
     * \param key The RSAPublicKey to send.
     * 			Can be null for the secound part if there is no support for extended apdus.
     */
    private void sendRSAPublicKey(APDU apdu, RSAPublicKey key) {

        short pos = 0;
        short size = key.getSize();
        byte[] ram_buf = transmitManager.GetRamBuffer();
        transmitManager.ClearRamBuffer();

        ram_buf[pos++] = (byte) 0x7F; // Interindustry template for nesting one set of public key data objects.
        ram_buf[pos++] = (byte) 0x49; // "

        if (size < (short) 2048) {
            ram_buf[pos++] = (byte) 0x81; // Length field: 2 Bytes.
            ram_buf[pos++] = (byte) ((size / 8) + 8);
        } else {
            ram_buf[pos++] = (byte) 0x82; // Length field: 3 Bytes.
            Util.setShort(ram_buf, pos, (short)((size / 8) + 9));
            pos += 2;
        }

        ram_buf[pos++] = (byte) 0x81; // RSA public key modulus tag.
        if (size < (short) 2048) {
            ram_buf[pos++] = (byte) 0x81; // Length field: 2 Bytes.
            ram_buf[pos++] = (byte) (size / 8);
        } else {
            ram_buf[pos++] = (byte) 0x82; // Length field: 3 Bytes.
            Util.setShort(ram_buf, pos, (short)(size / 8));
            pos += 2;
        }
        pos += key.getModulus(ram_buf, pos);
        ram_buf[pos++] = (byte) 0x82; // RSA public key exponent tag.
        ram_buf[pos++] = (byte) 0x03; // Length: 3 Bytes.
        pos += key.getExponent(ram_buf, pos);

        transmitManager.sendDataFromRamBuffer(apdu, (short)0, pos);
    }



    /**
     * \brief Process the MANAGE SECURITY ENVIRONMENT apdu (INS = 22).
     *
     * \attention Only SET is supported. RESTORE will reset the security environment.
     *				The security environment will be cleared upon deselection of the applet.
     * 				STOREing and ERASEing of security environments is not supported.
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_WRONG_LENGTH, SW_DATA_INVALID,
     *						SW_INCORRECT_P1P2, SW_FUNC_NOT_SUPPORTED, SW_COMMAND_NOT_ALLOWED.
     */
    public void processManageSecurityEnvironment(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short pos = 0;
        byte algRef = 0;
        byte privKeyRef = -1;
        CRTKeyFile crt = null;

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();

        // TLV structure consistency check.
        if( ! UtilTLV.isTLVconsistent(buf, ISO7816.OFFSET_CDATA, lc)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        /* Extract data: */
        switch(p1) {
        case (byte) 0x81:
        // SET Verification, encipherment, external authentication and key agreement.
        case (byte) 0xC1:
            // Private key reference (Index in keys[]-array).
            try {
                pos = UtilTLV.findTag(buf, ISO7816.OFFSET_CDATA, (byte) lc, (byte) 0x83);
            } catch (Exception e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(buf[++pos] != (byte) 0x01 ) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            privKeyRef = buf[++pos];
            algRef = (byte) 0x02;
            break;
        case (byte) 0x41:
            // SET Computation, decipherment, internal authentication and key agreement.

            // Algorithm reference.
            try {
                pos = UtilTLV.findTag(buf, ISO7816.OFFSET_CDATA, (byte) lc, (byte) 0x80);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(buf[++pos] != (byte) 0x01) { // Length must be 1.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            // Set the current algorithm reference.
            algRef = buf[++pos];

            // Private key reference (Index in keys[]-array).
            try {
                pos = UtilTLV.findTag(buf, ISO7816.OFFSET_CDATA, (byte) lc, (byte) 0x84);
            } catch (Exception e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(buf[++pos] != (byte) 0x01) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            privKeyRef = buf[++pos];
            break;

        case (byte) 0xF3:
            // RESTORE // Set sec env constants to default values.
            algRef = 0;
            privKeyRef = -1;
            break;

        case (byte) 0xF4: // ERASE
        case (byte) 0xF2: // STORE
        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        if(privKeyRef == -1) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        try {
            crt = fs.findKeyCRT(privKeyRef);
        } catch (NotFoundException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        try {
            crt.CheckUsage(p2, algRef);
        } catch (NotFoundException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        crt.CheckPermission(pinManager, File.ACL_OP_KEY_MANAGE_SEC_ENV);

        if (p1 == (byte) 0xc1 || p1 == (byte) 0x81) {
            pinManager.SetKeyReference(crt);
        } else {
            pinManager.SetKeyReference(null);
        }

        // Finally, update the security environment.
        currentAlgorithmRef[0] = algRef;
        currentKey[0] = crt;

    }

    /**
     * \brief Process the PERFORM SECURITY OPERATION apdu (INS=2A).
     *
     * This operation is used for cryptographic operations
     * (Computation of digital signatures, decrypting.).
     *
     * \param apdu The PERFORM SECURITY OPERATION apdu.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_INCORRECT_P1P2 and
     * 			the ones from computeDigitalSignature() and decipher().
     */
    private void processPerformSecurityOperation(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if(p1 == (byte) 0x9E && p2 == (byte) 0x9A) {
            computeDigitalSignature(apdu);
        } else if(p1 == (byte) 0x80 && p2 == (byte) 0x86) {
            decipher(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

    }

    /**
     * \brief Decipher the data from the apdu using the private key referenced by
     * 			an earlier MANAGE SECURITY ENVIRONMENT apdu.
     *
     * \param apdu The PERFORM SECURITY OPERATION apdu with P1=80 and P2=86.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_WRONG_LENGTH and
     *						SW_WRONG_DATA
     */
    private void decipher(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short offset_cdata;
        short lc;
        short decLen = -1;
        byte[] ram_buf = transmitManager.GetRamBuffer();
        Cipher cipher = null;

        lc = transmitManager.doChainingOrExtAPDU(apdu);
        offset_cdata = 0;

        // Padding indicator should be "No further indication".
        if(buf[offset_cdata] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        switch((byte) (currentAlgorithmRef[0] & 0xF0)) {

        case (byte) 0x80:
            cipher = rsaOaepCipher;
            break;
        case (byte) 0x40:
            cipher = rsaPkcs1Cipher;
            break;
        case (byte) 0x00:
            cipher = rsaRawCipher;
            break;
        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        // Get the key - it must be an RSA private key,
        // checks have been done in MANAGE SECURITY ENVIRONMENT.
        CRTKeyFile key = (CRTKeyFile) currentKey[0];
        PrivateKey theKey = key.GetKey().getPrivate();

        // Check the length of the cipher.
        // Note: The first byte of the data field is the padding indicator
        //		 and therefor not part of the ciphertext.
        if(lc !=  (short)(theKey.getSize() / 8)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        cipher.init(theKey, Cipher.MODE_DECRYPT);

        try {
            decLen = cipher.doFinal(ram_buf, (short) 0, lc,
                                    buf, (short) 0);
        } catch(CryptoException e) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // We have to send at most 256 bytes. A short APDU can handle that - only one send operation neccessary.
        apdu.setOutgoingAndSend((short)0, decLen);
    }

    /**
     * \brief Compute a digital signature of the data from the apdu
     * 			using the private key referenced by	an earlier
     *			MANAGE SECURITY ENVIRONMENT apdu.
     *
     * \attention The apdu should contain a hash, not raw data for RSA keys.
     * 				PKCS1 padding will be applied if neccessary.
     *
     * \param apdu The PERFORM SECURITY OPERATION apdu with P1=9E and P2=9A.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_WRONG_LENGTH
     * 						and SW_UNKNOWN.
     */
    private void computeDigitalSignature(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short lc, le;
        short sigLen = 0;
        PrivateKey rsaKey = null;
        byte[] ram_buf = transmitManager.GetRamBuffer();
        CRTKeyFile key = (CRTKeyFile) currentKey[0];

        switch((byte) (currentAlgorithmRef[0] & 0xF0)) {
        case (byte) 0x10:
            // padding made off card -> raw encryption to be performed
            lc = transmitManager.doChainingOrExtAPDU(apdu);

            // RSA signature operation.
            rsaKey = key.GetKey().getPrivate();

            rsaRawCipher.init(rsaKey, Cipher.MODE_ENCRYPT);
            sigLen = rsaRawCipher.doFinal(ram_buf, (short) 0, lc, ram_buf, (short)0);
            // A single short APDU can handle 256 bytes - only one send operation neccessary.
            le = apdu.setOutgoing();
            if(le > 0 && le < sigLen) {
                ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
            }
            apdu.setOutgoingLength(sigLen);
            apdu.sendBytesLong(ram_buf, (short) 0, sigLen);
            break;
        case (byte) 0x50:
            // rsa padding made by the card, only the hash is provided

            // Receive.
            // Bytes received must be Lc.
            lc = apdu.setIncomingAndReceive();

            // RSA signature operation.
            rsaKey = key.GetKey().getPrivate();

            if(lc > (short) 247) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            
            rsaPkcs1Cipher.init(rsaKey, Cipher.MODE_ENCRYPT);
            sigLen = rsaPkcs1Cipher.doFinal(buf, ISO7816.OFFSET_CDATA, lc, ram_buf, (short)0);

            /*if(sigLen != 256) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }*/

            // A single short APDU can handle 256 bytes - only one send operation neccessary.
            le = apdu.setOutgoing();
            if(le > 0 && le < sigLen) {
                ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
            }
            apdu.setOutgoingLength(sigLen);
            apdu.sendBytesLong(ram_buf, (short) 0, sigLen);
            break;

        default:
            // Wrong/unknown algorithm.
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * \brief Process the PUT DATA apdu (INS=DB).
     *
     * PUT DATA is currently used for private key import.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_INCORRECT_P1P2
     */
    private void processPutData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if(p1 == (byte) 0x3F && p2 == (byte) 0xFF) {
            importPrivateKey(apdu);
        } else {
            fs.processPutData(apdu);
        }
    }

    /**
     * \brief Upload and import a usable private key.
     *
     * A preceeding MANAGE SECURITY ENVIRONMENT is necessary (like with key-generation).
     * The format of the data (of the apdu) must be BER-TLV,
     * Tag 7F48 ("T-L pair to indicate a private key data object") for RSA or tag 0xC1
     * for EC keys, containing the point Q.
     *
     * For RSA, the data to be submitted is quite large. It is required that command chaining is
     * used for the submission of the private key. One chunk of the chain (one apdu) must contain
     * exactly one tag (0x92 - 0x96). The first apdu of the chain must contain the outer tag (7F48).
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_DATA_INVALID, SW_WRONG_LENGTH.
     */
    private void importPrivateKey(APDU apdu) throws ISOException {
        short recvLen;
        short len = 0, pos = 0;
        short innerPos = 0, innerLen = 0;
        byte[] flash_buf = null;
        byte privKeyRef = -1;
        CRTKeyFile crt = null;

        if( ! DEF_PRIVATE_KEY_IMPORT_ALLOWED) {
            ISOException.throwIt(ErrorCode.SW_COMMAND_NOT_ALLOWED_GENERAL);
        }
        try
        {
            // flash buffer is allocated in the next instruction
            recvLen = transmitManager.doChainingOrExtAPDUFlash(apdu);
            // if these 2 lines are reversed, flash_buf can be null
            flash_buf = transmitManager.GetFlashBuffer();
            
            try {
                innerPos = UtilTLV.findTag(flash_buf, (short) 0, recvLen, (byte) 0x70);
                innerLen = UtilTLV.decodeLengthField(flash_buf, (short)(innerPos+1));
                innerPos += 1 + UtilTLV.getLengthFieldLength(flash_buf, (short)(innerPos+1));
            } catch (Exception e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
    
            try {
                pos = UtilTLV.findTag(flash_buf, innerPos, innerLen, (byte) 0x84);
                len = UtilTLV.decodeLengthField(flash_buf, (short)(innerPos+1));
                if (len != 1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                privKeyRef = flash_buf[(short) (pos+2)];
            } catch (Exception e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            try {
                pos = UtilTLV.findTag(flash_buf, innerPos, innerLen, (byte) 0xA5);
                len = UtilTLV.decodeLengthField(flash_buf, (short)(innerPos+1));
            } catch (Exception e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(privKeyRef == -1) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            try {
                crt = fs.findKeyCRT(privKeyRef);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
    
            crt.CheckPermission(pinManager, File.ACL_OP_KEY_PUTKEY);
    
            try {
                crt.importKey(flash_buf, pos, len);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            // clear ressource and avoid leaking a private key in flash (if the private key is deleted after)
            transmitManager.ClearFlashBuffer();
        } catch(ISOException e) {
            if (e.getReason() != ISO7816.SW_NO_ERROR) {                
                // clear ressource and avoid leaking a private key in flash (if the private key is deleted after)
                transmitManager.ClearFlashBuffer();
            }
            throw e;
        }
        
    }

} // class GidsApplet
