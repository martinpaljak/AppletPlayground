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

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * \brief class used to encapsulte authentication functions
 */
public class GidsPINManager {

    /* PIN, PUK and key realted constants */
    // PIN:
    private static final byte PIN_MAX_TRIES = 3;
    private static final byte PIN_MIN_LENGTH = 4;
    private static final byte PIN_MAX_LENGTH = 16;
    // state for admin authentication
    private static final byte ADMIN_NOT_AUTHENTICATED = 0;
    private static final byte EXTERNAL_CHALLENGE = 1;
    private static final byte MUTUAL_CHALLENGE = 2;
    private static final byte EXTERNAL_AUTHENTICATED = 3;
    private static final byte MUTUAL_AUTHENTICATED = 4;

    private GidsPIN pin_pin = null;

    private boolean isInInitializationMode = true;

    private byte[] ExternalChallenge = null;
    private byte[] CardChallenge = null;
    private Object[] KeyReference = null;
    private byte[] buffer = null;
    private byte[] sharedKey = null;
    private byte[] status = null;

    public GidsPINManager() {
        pin_pin = new GidsPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH, PIN_MIN_LENGTH);
        ExternalChallenge = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        CardChallenge = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        KeyReference = JCSystem.makeTransientObjectArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        buffer = JCSystem.makeTransientByteArray((short)40, JCSystem.CLEAR_ON_DESELECT);
        sharedKey = JCSystem.makeTransientByteArray((short)40, JCSystem.CLEAR_ON_DESELECT);
        status = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
    }

    private GidsPIN GetPINByReference(byte reference) throws NotFoundException {
        switch(reference) {
        case (byte) 0x80:
        case (byte) 0x00:
            return pin_pin;
        case (byte) 0x81:
        //no PUK on v2 of the card
        default:
            throw NotFoundException.getInstance();
        }
    }

    public void SetInitializationMode(boolean value) {
        isInInitializationMode = value;
        if (value == false) {
            DeauthenticateAllPin();
        }
    }

    public void DeauthenticateAllPin() {
        pin_pin.reset();
        // deauthenticate admin key
        status[0] = ADMIN_NOT_AUTHENTICATED;
        ClearChallengeData();
        // clear shared key
        Util.arrayFillNonAtomic(sharedKey, (short) 0,   (short) sharedKey.length, (byte)0x00);
        KeyReference[0] = null;
    }

    private boolean CheckUserAuthentication() {
        if (!isInInitializationMode) {
            if (!pin_pin.isValidated()) {
                return false;
            }
        }
        return true;
    }

    private boolean CheckExternalOrMutualAuthentication() {
        if (!isInInitializationMode) {
            if (status[0] != EXTERNAL_AUTHENTICATED && status[0] != MUTUAL_AUTHENTICATED) {
                return false;
            }
        }
        return true;
    }

    public void SetKeyReference(CRTKeyFile crt) {
        KeyReference[0] = crt;
    }


    /**
     * \brief throw a SW_SECURITY_STATUS_NOT_SATISFIED exception if not allowed
     */
    public void CheckACL(byte acl) {
        if(acl == (byte) 0x00) { // No restrictions.
            return;
        } else if(acl == (byte) 0xFF) { // Never.
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte SEID = (byte)(acl & (byte)0x0F);
        // contact / contact less ACL
        if (SEID > 0) {
            byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
            if (SEID == 1) {
                // contact operation
                if (protocol != APDU.PROTOCOL_MEDIA_USB && protocol != APDU.PROTOCOL_MEDIA_DEFAULT) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            } else if (SEID == 2) {
                // contact less operation
                if (protocol != APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A && protocol != APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            }
        }
        byte authentication = (byte)(acl & (byte)0xF0);
        if(authentication  == (byte) 0x90) {
            // PIN required.
            if (CheckUserAuthentication()) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if ((byte)(authentication&(byte)0x90) == (byte)0x10) {
            // PIN can valid the ACL
            if (CheckUserAuthentication()) {
                return;
            }
            // else continue
        }
        if(authentication  == (byte) 0xA0) {
            // external / mutal authentication mandatory
            if (CheckExternalOrMutualAuthentication()) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if((authentication&(byte)0xA0) == (byte)0x20) {
            // external or mutal authentication optional
            if (CheckExternalOrMutualAuthentication()) {
                return;
            }
            // else continue
        }
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    /**
     * \brief Process the VERIFY apdu (INS = 20).
     *
     * This apdu is used to verify a PIN and authenticate the user. A counter is used
     * to limit unsuccessful tries (i.e. brute force attacks).
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_INCORRECT_P1P2, ISO7816.SW_WRONG_LENGTH, SW_PIN_TRIES_REMAINING.
     */
    public void processVerify(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short lc;
        GidsPIN pin = null;

        // P1P2 0001 only at the moment. (key-reference 01 = PIN)
        if(buf[ISO7816.OFFSET_P1] != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (buf[ISO7816.OFFSET_P2] == (byte) 0x82) {
            // special resetting code for GIDS
            DeauthenticateAllPin();
            return;
        }

        try {
            pin = GetPINByReference(buf[ISO7816.OFFSET_P2]);
        } catch(NotFoundException e) {
            ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
        }

        lc = apdu.setIncomingAndReceive();

        if (pin.getTriesRemaining() == (byte) 0) {
            // pin blocked
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        }

        // Lc might be 0, in this case the caller checks if verification is required.
        if((lc > 0 && (lc < pin.GetMinPINSize()) || lc > pin.GetMaxPINSize())) {
            ISOException.throwIt((short) (ErrorCode.SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        }

        // Caller asks if verification is needed.
        if(lc == 0) {
            if (!isInInitializationMode) {
                // Verification required, return remaining tries.
                ISOException.throwIt((short)(ErrorCode.SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
            } else {
                // No verification required.
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
            }
        }

        // Check the PIN.
        if(!pin.check(buf, ISO7816.OFFSET_CDATA, (byte) lc)) {
            ISOException.throwIt((short)(ErrorCode.SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        } else {

        }
    }

    /**
     * \brief Process the CHANGE REFERENCE DATA apdu (INS = 24).
     *
     * If the state is STATE_CREATION, we can set the PUK without verification.
     * The state will advance to STATE_INITIALISATION (i.e. the PUK must be set before the PIN).
     * In a "later" state the user must authenticate himself to be able to change the PIN.
     *
     * \param apdu The apdu.
     *
     * \throws ISOException SW_INCORRECT_P1P2, ISO7816.SW_WRONG_LENGTH, SW_PIN_TRIES_REMAINING.
     */
    public void processChangeReferenceData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        GidsPIN pin = null;

        lc = apdu.setIncomingAndReceive();

        if (p1 == (byte) 0x01) {
            try {
                pin = GetPINByReference(p2);
            } catch(NotFoundException e) {
                ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            }

            // Check length.
            pin.CheckLength((byte) lc);

            // authentication not needed for the first pin set
            if(!isInInitializationMode) {
                if (!pin.isValidated()) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            }
            // Set PIN value
            pin.update(buf, ISO7816.OFFSET_CDATA, (byte)lc);
            if(isInInitializationMode) {
                pin.resetAndUnblock();
            }

        } else if (p1 == (byte) 0x00) {
            try {
                pin = GetPINByReference(buf[ISO7816.OFFSET_P2]);
            } catch(NotFoundException e) {
                ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            }

            // Check PIN lengths
            if(lc > (short)(pin.GetMaxPINSize() *2) || lc < (short)(pin.GetMinPINSize() *2)) {
                ISOException.throwIt((short) (ErrorCode.SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
            }

            byte currentPinLength = pin.GetCurrentPINLen();
            // if the current pin is very long and the tested pin is very short, force the verification to decreate the remaining try count
            // do not allow the revelation of currentPinLength until pin.check is done
            if (lc < currentPinLength) {
                currentPinLength = (byte) lc;
            }
            if (pin.getTriesRemaining() == (byte) 0) {
                // pin blocked
                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
            }
            // Check the old PIN.
            if(!pin.check(buf, ISO7816.OFFSET_CDATA, currentPinLength)) {
                ISOException.throwIt((short)(ErrorCode.SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
            }
            if(lc > (short)(pin.GetMaxPINSize() + currentPinLength) || lc < (short)(currentPinLength + pin.GetMinPINSize())) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            // UPDATE PIN
            pin.update(buf, (short) (ISO7816.OFFSET_CDATA+currentPinLength), (byte) (lc - currentPinLength));
            pin.setAsAuthenticated();
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }// end processChangeReferenceData()




    /**
     * \brief Process the RESET RETRY COUNTER apdu (INS = 2C).
     *
     * This is used to unblock the PIN with the PUK and set a new PIN value.
     *
     * \param apdu The RESET RETRY COUNTER apdu.
     *
     * \throw ISOException SW_COMMAND_NOT_ALLOWED, ISO7816.SW_WRONG_LENGTH, SW_INCORRECT_P1P2,
     *			SW_PIN_TRIES_REMAINING.
     */
    public void	processResetRetryCounter(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        GidsPIN pin = null;

        if(isInInitializationMode) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        if(p1 == (byte) 0x02) {
            // this suppose a previous authentication of the admin via
            // external or mutual authenticate
            lc = apdu.setIncomingAndReceive();
            // only P2 = 80 is specified
            if (p2 != (byte) 0x80) {
                ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            }
            try {
                pin = GetPINByReference(p2);
            } catch(NotFoundException e) {
                ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            }
            if (!CheckExternalOrMutualAuthentication()) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            // Check length.
            pin.CheckLength((byte) lc);
            // Set PIN value
            pin.update(buf, ISO7816.OFFSET_CDATA, (byte)lc);
            pin.resetAndUnblock();
            // admin is deauthenticated at the end of the process
            DeauthenticateAllPin();
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

    }

    /**
     * \brief Process the general authentication process
     */
    public void processGeneralAuthenticate(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;

        if(isInInitializationMode) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        if(p1 != (byte) 0x00 || p2 != (byte) 0x00 ) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();

        short innerPos = 0, innerLen = 0;
        if (buf[ISO7816.OFFSET_CDATA] != (byte) 0x7C) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }


        try {
            innerLen = UtilTLV.decodeLengthField(buf, (short) (ISO7816.OFFSET_CDATA+1));
            innerPos = (short) (ISO7816.OFFSET_CDATA + 1 + UtilTLV.getLengthFieldLength(buf, (short) (ISO7816.OFFSET_CDATA+1)));
        } catch (InvalidArgumentsException e1) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // inner functions never return if their input tag is found
        if (CheckForExternalChallenge(apdu, buf, innerPos, innerLen)) {
            return;
        }
        if (CheckForChallengeResponse(apdu, buf, innerPos, innerLen)) {
            return;
        }
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    /**
     * \brief clear the data used for admin authentication
     */
    private void ClearChallengeData() {
        Util.arrayFillNonAtomic(ExternalChallenge, (short) 0,   (short) ExternalChallenge.length, (byte)0x00);
        Util.arrayFillNonAtomic(CardChallenge, (short) 0,   (short) CardChallenge.length, (byte)0x00);
        Util.arrayFillNonAtomic(buffer, (short) 0,   (short) buffer.length, (byte)0x00);
        Util.arrayFillNonAtomic(status, (short) 0,   (short) status.length, (byte)0x00);
    }

    /**
     * \brief handle the first part of the general authenticate APDU
     */
    private boolean CheckForExternalChallenge(APDU apdu, byte[] buf, short innerPos, short innerLen) {
        short pos = 0, len = 0;
        try {
            pos = UtilTLV.findTag(buf, innerPos, innerLen, (byte) 0x81);
            if (buf[(short) (pos+1)] == 0) {
                // zero len TLV allowed
                len = 0;
            } else {
                len = UtilTLV.decodeLengthField(buf, (short)(pos+1));
            }
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (NotFoundException e) {
            return false;
        }
        ClearChallengeData();

        pos += 1 + UtilTLV.getLengthFieldLength(buf, (short)(pos+1));
        // challenge size = 16 => mutual authentication
        // challenge size = 0 => external authentication, request for a challenge
        if (len == (short)16) {
            Util.arrayCopyNonAtomic(buf, pos, ExternalChallenge, (short) 0, len);
            // generate a 16 bytes challenge
            status[0] = MUTUAL_CHALLENGE;
        } else if (len == 0) {
            // generate a 8 bytes challenge
            len = 8;
            status[0] = EXTERNAL_CHALLENGE;
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        randomData.generateData(CardChallenge, (short) 0, len);

        pos = 0;
        buf[pos++] = (byte) 0x7C;
        buf[pos++] = (byte) (len + 2);
        buf[pos++] = (byte) 0x81;
        buf[pos++] = (byte) (len);
        Util.arrayCopyNonAtomic(CardChallenge, (short) 0, buf, pos, len);
        apdu.setOutgoingAndSend((short)0, (short) (len + 4));
        return true;
    }

    /**
     * \brief handle the second part of the general authenticate APDU
     */
    private boolean CheckForChallengeResponse(APDU apdu, byte[] buf, short innerPos, short innerLen) {
        short pos = 0, len = 0;
        try {
            pos = UtilTLV.findTag(buf, innerPos, innerLen, (byte) 0x82);
            len = UtilTLV.decodeLengthField(buf, (short)(pos+1));
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (NotFoundException e) {
            return false;
        }

        pos += 1 + UtilTLV.getLengthFieldLength(buf, (short)(pos+1));
        if (len > (short)40) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (status[0] == MUTUAL_CHALLENGE) {
            Cipher cipherDES = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
            DESKey key = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
            key.setKey(((CRTKeyFile)(KeyReference[0])).GetSymmectricKey(), (short) 0);

            //decrypt message
            cipherDES.init(key, Cipher.MODE_DECRYPT);
            cipherDES.doFinal(buf, pos, len, buffer, (short) 0);

            if (Util.arrayCompare(buffer, (short) 0, CardChallenge, (short) 0, (short) 16) != 0) {
                ClearChallengeData();
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            if (Util.arrayCompare(buffer, (short) 16, ExternalChallenge, (short) 0, (short) 16) != 0) {
                ClearChallengeData();
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            Util.arrayCopy(buffer, (short) 32, sharedKey, (short) 0, (short) (len - 32));

            RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            randomData.generateData(sharedKey, (short) (len - 32), (short) (len - 32));

            Util.arrayCopy(buffer, (short) 32, sharedKey, (short) (len - 32), (short) (len - 32));

            cipherDES.init(key, Cipher.MODE_ENCRYPT);
            cipherDES.doFinal(buffer, (short) 0, len, buf, (short) 0);

            // avoid replay attack
            ClearChallengeData();
            status[0] = MUTUAL_AUTHENTICATED;

            apdu.setOutgoing();
            apdu.setOutgoingLength(len);
            apdu.sendBytes((short) 0, len);
        } else if (status[0] == EXTERNAL_CHALLENGE) {
            Cipher cipherDES = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
            DESKey key = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
            key.setKey(((CRTKeyFile)(KeyReference[0])).GetSymmectricKey(), (short) 0);

            //decrypt message
            cipherDES.init(key, Cipher.MODE_DECRYPT);
            cipherDES.doFinal(buf, pos, len, buffer, (short) 0);

            if (Util.arrayCompare(buffer, (short) 0, CardChallenge, (short) 0, (short) 8) != 0) {
                ClearChallengeData();
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // avoid replay attack
            ClearChallengeData();
            status[0] = EXTERNAL_AUTHENTICATED;
        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        return true;
    }

    /**
     * \brief return information regarding the PIN
     */
    public void returnPINStatus(APDU apdu, short id) {
        byte[] buf = apdu.getBuffer();
        GidsPIN pin = null;
        switch(id) {
        default:
            ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            break;
        case (short) 0x7F71:
        case (short) 0x7F72:
            pin = pin_pin;
            break;
        }

        Util.setShort(buf, (short) 0, id);
        buf[2] = (byte) 0x06;
        buf[3] = (byte) 0x97;
        buf[4] = (byte) 0x01;
        buf[5] = pin.getTriesRemaining();
        buf[6] = (byte) 0x93;
        buf[7] = (byte) 0x01;
        buf[8] = pin.getTryLimit();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)9);
        apdu.sendBytes((short) 0, (short) 9);

    }

}
