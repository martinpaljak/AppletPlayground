/*
 * DrivingLicenseApplet - A reference implementation of the ISO18013 standards.
 * Based on the passport applet code developed by the JMRTD team, see
 * http://jmrtd.org
 *
 * Copyright (C) 2006  SoS group, Radboud University
 * Copyright (C) 2009  Wojciech Mostowski, Radboud University
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

package org.isodl.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

/**
 * Encapsulation class for a card verifiable certificate according to ISO18013.
 * We assume there is only one instance of this class for the current EAP
 * certificate in chain. The root ana alternate root certificate data is also
 * stored in this class in persistent arrays.
 * 
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 * 
 */
public class CVCertificate {

    /**
     * Offsets to where the particular data (offsets & lengths) of the current
     * certificate is (temporarily) stored in the data array
     */
    private static final short OFFSET_PUB_KEY_MODULUS_OFFSET = 0;
    private static final short OFFSET_PUB_KEY_MODULUS_LENGTH = 1;
    private static final short OFFSET_PUB_KEY_EXPONENT_OFFSET = 2;
    private static final short OFFSET_PUB_KEY_EXPONENT_LENGTH = 3;
    private static final short OFFSET_SUB_ID_OFFSET = 4;
    private static final short OFFSET_SUB_ID_LENGTH = 5;
    private static final short OFFSET_AUTHORIZATION_OFFSET = 6;
    private static final short OFFSET_EFF_DATE_OFFSET = 7;
    private static final short OFFSET_EXP_DATE_OFFSET = 8;
    private static final short OFFSET_SIGNATURE_OFFSET = 9;
    private static final short OFFSET_SIGNATURE_LENGTH = 10;
    private static final short OFFSET_BODY_LENGTH = 11;

    /** Different tags to parse */
    private static final short TAG_CERT_BODY = 0x7F4E;
    private static final short TAG_CERT_VERSION = 0x5F29;
    private static final short TAG_AUTH_ID = 0x42;
    private static final short TAG_PUB_KEY = 0x7F49;
    private static final short TAG_OID = 0x06;
    private static final short TAG_MODULUS = 0x81;
    private static final short TAG_EXPONENT = 0x82;
    private static final short TAG_SUBJECT_ID = 0x5F20;
    private static final short TAG_SUBJECT_AUTH = 0x7F4C;
    private static final short TAG_AUTHORIZATION = 0x53;
    private static final short TAG_EFF_DATE = 0x5F25;
    private static final short TAG_EXP_DATE = 0x5F24;
    private static final short TAG_SIGNATURE = 0x5F37;

    private static final byte AUTH_LEN_MASK = 0x0F;
    private static final byte ENTITY_MASK = (byte) 0xF0;
    private static final byte TRUST_ROOT = (byte) 0x20;
    private static final byte TRUST_TIME = (byte) 0x10;

    /** The ASN1 OID of the only algorithm our certificates support */
    private static final byte[] RSA_SHA1_OID = { 0x28, (byte) 0x81,
            (byte) 0x8C, 0x5D, 0x03, 0x01, 0x14 };

    /** The terminal OID, see ISO18013-3, C.2.1.5 */
    private static final byte[] AR_TERMINAL_OID = { 0x28, (byte) 0x81,
            (byte) 0x8C, 0x5D, 0x03, 0x03, 0x01 };

    private short[] data;
    private Object[] source;

    private RSAPublicKey currentCertPublicKey;
    private byte[] effectiveCertAuthorization;
    private byte[] currentCertAuthorization;
    private byte[] currentCertSubjectId;
    private byte[] currentCertEffDate;
    private byte[] currentCertExpDate;

    /**  2009-01-01 */
    private byte[] currentDate = { 0x00, 0x09, 0x00, 0x01, 0x00, 0x01 }; 

    private static final byte CERT_ROOT = 1;
    private static final byte CERT_ALT = 2;
    
    private byte[] currentCertNum;

    private byte[] rootCertHolderReference;
    private byte[] rootCertPublicKeyData;
    private byte[] rootCertAuthorization;
    private byte[] rootCertEffDate;
    private byte[] rootCertExpDate;

    private byte[] altCertHolderReference;
    private byte[] altCertPublicKeyData;
    private byte[] altCertAuthorization;
    private byte[] altCertEffDate;
    private byte[] altCertExpDate;

    private Signature signature;

    private byte[] comFile;
    private short cvcaRootIndex;
    private short cvcaAltIndex;
    
    CVCertificate() {
        data = JCSystem.makeTransientShortArray(
                (short) (OFFSET_BODY_LENGTH + 1), JCSystem.CLEAR_ON_DESELECT);
        source = JCSystem.makeTransientObjectArray((short) 1,
                JCSystem.CLEAR_ON_DESELECT);
        effectiveCertAuthorization = JCSystem.makeTransientByteArray((short)4,
                JCSystem.CLEAR_ON_DESELECT);
        currentCertAuthorization = JCSystem.makeTransientByteArray((short)4,
                JCSystem.CLEAR_ON_DESELECT);
        currentCertSubjectId = JCSystem.makeTransientByteArray((short) 17,
                JCSystem.CLEAR_ON_DESELECT);
        currentCertPublicKey = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        currentCertEffDate = JCSystem.makeTransientByteArray((short)6,
                JCSystem.CLEAR_ON_DESELECT);
        currentCertExpDate = JCSystem.makeTransientByteArray((short)6,
                JCSystem.CLEAR_ON_DESELECT);
        currentCertNum = JCSystem.makeTransientByteArray((short)1,
                JCSystem.CLEAR_ON_DESELECT);
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
    }

    
    /**
     * Checks if the provided subject id matches the current one, if any, or selects one of the root ones.
     * 
     * @param data
     *            byte[] with the subject id
     * @param offset
     *            offset to data
     * @param length
     *            length of the data
     * @return true if the current subject match or it was possible to select one of the root ones 
     */
    boolean selectSubjectId(byte[] data, short offset, short length) {
        if(currentCertSubjectId[0] == 0) {
            if(rootCertHolderReference != null && rootCertHolderReference[0] == (byte)length) {
                if(Util.arrayCompare(rootCertHolderReference, (short)1, data, offset, length) == 0) {
                    setupCurrentKey(rootCertHolderReference, rootCertPublicKeyData, rootCertAuthorization, rootCertEffDate, rootCertExpDate);
                    currentCertNum[0] = CERT_ROOT;
                    return true;
                }
            }else if(altCertHolderReference != null && altCertHolderReference[0] == (byte)length) {
                if(Util.arrayCompare(altCertHolderReference, (short)1, data, offset, length) == 0) {
                  setupCurrentKey(altCertHolderReference, altCertPublicKeyData, altCertAuthorization, altCertEffDate, altCertExpDate);
                  currentCertNum[0] = CERT_ALT;
                  return true;
                }
            }
            return false;
        }
        return length == currentCertSubjectId[0] && Util.arrayCompare(currentCertSubjectId, (short) 1, data, offset,
                length) == 0;
    }

    // Sets up the current certificate data from the certificate contained in one
    // of the CA certificates stored in this object
    private void setupCurrentKey(byte[] certHolderReference, byte[] certPublicKeyData, byte[] certAuthorization, byte[] certEffDate, byte[] certExpDate) {
        Util.arrayCopyNonAtomic(certHolderReference, (short)0, currentCertSubjectId, (short)0, (short)certHolderReference.length);
        Util.arrayCopyNonAtomic(certAuthorization, (short)0, effectiveCertAuthorization, (short)0, (short)effectiveCertAuthorization.length);
        Util.arrayCopyNonAtomic(certAuthorization, (short)0, currentCertAuthorization, (short)0, (short)currentCertAuthorization.length);
        Util.arrayCopyNonAtomic(certEffDate, (short)0, currentCertEffDate, (short)0, (short)6);
        Util.arrayCopyNonAtomic(certExpDate, (short)0, currentCertExpDate, (short)0, (short)6);
        currentCertPublicKey.setExponent(certPublicKeyData, (short)0, (short)3);
        currentCertPublicKey.setModulus(certPublicKeyData, (short)3, (short)128);
    }

    // Sets up the current certificate data from the certificate contained in source and data.
    private void setupCurrentKeyFromCurrentCertificate() {
        byte[] certData = (byte[])source[0];
        short certHolderReferenceOffset = data[OFFSET_SUB_ID_OFFSET];
        short certHolderReferenceLength = data[OFFSET_SUB_ID_LENGTH];
        short pubKeyExpOffset = data[OFFSET_PUB_KEY_EXPONENT_OFFSET];
        short pubKeyExpLength = data[OFFSET_PUB_KEY_EXPONENT_LENGTH];
        short pubKeyModOffset = data[OFFSET_PUB_KEY_MODULUS_OFFSET];
        short pubKeyModLength = data[OFFSET_PUB_KEY_MODULUS_LENGTH];
        short authorizationOffset = data[OFFSET_AUTHORIZATION_OFFSET];
        short effDateOffset = data[OFFSET_EFF_DATE_OFFSET];
        short expDateOffset = data[OFFSET_EXP_DATE_OFFSET];
        Util.arrayCopyNonAtomic(certData, certHolderReferenceOffset, currentCertSubjectId, (short)1, certHolderReferenceLength);
        currentCertSubjectId[0] = (byte)certHolderReferenceLength;
        currentCertPublicKey.setExponent(certData, pubKeyExpOffset, pubKeyExpLength);
        currentCertPublicKey.setModulus(certData, pubKeyModOffset, pubKeyModLength);
        byte nParent = (byte) (effectiveCertAuthorization[0] & AUTH_LEN_MASK);
        byte nCurrent = (byte) (certData[authorizationOffset] & AUTH_LEN_MASK);
        if (nParent != AUTH_LEN_MASK) {
            if (nCurrent == AUTH_LEN_MASK) {
                nCurrent = nParent;
            } else {
                nParent--;
                if (nParent < nCurrent)
                    nCurrent = nParent;
            }
        }
        effectiveCertAuthorization[0] = (byte) ((byte) ((byte) (effectiveCertAuthorization[0] & certData[authorizationOffset]) & ENTITY_MASK) | nCurrent);
        for (short i = 1; i < 4; i++) {
            effectiveCertAuthorization[i] &= certData[(short) (authorizationOffset + i)];
        }
        Util.arrayCopyNonAtomic(certData, authorizationOffset, currentCertAuthorization, (short)0, (short)4);
        Util.arrayCopyNonAtomic(certData, effDateOffset, currentCertEffDate, (short)0, (short)6);
        Util.arrayCopyNonAtomic(certData, expDateOffset, currentCertExpDate, (short)0, (short)6);
    }

    /**
     * Cleans up the current certificate information.
     * 
     */
    void clear() {
        cleanArray(data);
        Util.arrayFillNonAtomic(effectiveCertAuthorization, (short) 0, (short) 4,
                (byte) 0);
        Util.arrayFillNonAtomic(currentCertAuthorization, (short) 0, (short) 4,
                (byte) 0);
        Util.arrayFillNonAtomic(currentCertSubjectId, (short) 0, (short) 17,
                (byte) 0);
        Util.arrayFillNonAtomic(currentCertEffDate, (short) 0, (short) 6,
                (byte) 0);
        Util.arrayFillNonAtomic(currentCertExpDate, (short) 0, (short) 6,
                (byte) 0);
        Util.arrayFillNonAtomic(currentCertNum, (short) 0, (short) 1,
                (byte) 0);
        currentCertPublicKey.clearKey();
        source[0] = null;
    }

    /**
     * Verify the current certificate (ie. the data in source) using the current
     * state of certificate verification data (publicKey, subject id, etc.) The
     * verification procedure is described in ISO18013-3 Section C.4.4.2.
     * 
     * @return true if certificate verification succeeds
     */
    boolean verify() {

        boolean result = (byte) (effectiveCertAuthorization[0] & AUTH_LEN_MASK) > 0;

        byte[] certData = (byte[])source[0];
        short bodyLength =data[OFFSET_BODY_LENGTH]; 
        short sigOffset =data[OFFSET_SIGNATURE_OFFSET]; 
        short sigLength =data[OFFSET_SIGNATURE_LENGTH]; 
        
        // check the actual signature
        signature.init(currentCertPublicKey, Signature.MODE_VERIFY);
        signature.update(certData, (short) 0, bodyLength);
        result = signature.verify(certData, bodyLength,
                (short) 0, certData, sigOffset, sigLength) && result;

        // check dates
        result = (compareDate(certData, data[OFFSET_EXP_DATE_OFFSET],
                currentDate, (short) 0) > 0)
                && result;

        short subjectIdOffset = data[OFFSET_SUB_ID_OFFSET];
        short subjectIdLength = data[OFFSET_SUB_ID_LENGTH];
        if((rootCertHolderReference != null && (byte)subjectIdLength == rootCertHolderReference[0] && 
                Util.arrayCompare(rootCertHolderReference, (short)1, certData, subjectIdOffset, subjectIdLength) == 0)
                ||
                (altCertHolderReference != null && (byte)subjectIdLength == altCertHolderReference[0] && 
                        Util.arrayCompare(altCertHolderReference, (short)1, certData, subjectIdOffset, subjectIdLength) == 0)){
                    result = false;
        }
        if (result) {
            setupCurrentKeyFromCurrentCertificate();
            // Conditions necessary to update the current date
            boolean setTime = (byte) (effectiveCertAuthorization[0] & TRUST_TIME) == TRUST_TIME;
            setTime = setTime && compareDate(currentCertEffDate, (short)0, currentDate, (short)0) > 0;
            // Conditions necessary to update the current trust root certificate
            boolean setCert = (byte) (effectiveCertAuthorization[0] & TRUST_ROOT) == TRUST_ROOT; 
            setCert = setCert && currentCertNum[0] == CERT_ROOT;
            setCert = setCert && compareDate(currentCertEffDate, (short)0,
                    rootCertEffDate, (short) 0) > 0;
            // If the current root is not yet expired save it to alternate root
            boolean setAlt = compareDate(rootCertExpDate, (short)0,
                    setTime ? currentCertEffDate : currentDate, (short) 0) >= 0;

            boolean cleanAlt = compareDate(altCertExpDate, (short)0,
                            setTime ? currentCertEffDate : currentDate, (short) 0) < 0;
                    
            if(setCert || setTime) {
                JCSystem.beginTransaction();
                if(setCert) {
                    if(setAlt) {
                      Util.arrayCopy(rootCertHolderReference, (short)0, altCertHolderReference, (short)0, (short)rootCertHolderReference.length);
                      Util.arrayCopy(rootCertPublicKeyData, (short)0, altCertPublicKeyData, (short)0, (short)rootCertPublicKeyData.length);
                      Util.arrayCopy(rootCertEffDate, (short)0, altCertEffDate, (short)0, (short)rootCertEffDate.length);
                      Util.arrayCopy(rootCertExpDate, (short)0, altCertExpDate, (short)0, (short)rootCertExpDate.length);
                      Util.arrayCopy(rootCertAuthorization, (short)0, altCertAuthorization, (short)0, (short)rootCertAuthorization.length);
                    }else if(cleanAlt) {
                        cleanArray(altCertHolderReference);
                        cleanArray(altCertPublicKeyData);
                        cleanArray(altCertEffDate);
                        cleanArray(altCertExpDate);
                        cleanArray(altCertAuthorization);
                    }
                    Util.arrayCopy(currentCertSubjectId, (short)0, rootCertHolderReference, (short)0, (short)17);
                    Util.arrayCopy(currentCertAuthorization, (short)0, rootCertAuthorization, (short)0, (short)17);
                    Util.arrayCopy(currentCertEffDate, (short)0, rootCertEffDate, (short)0, (short)6);
                    Util.arrayCopy(currentCertExpDate, (short)0, rootCertExpDate, (short)0, (short)6);
                    Util.arrayCopy(rootCertHolderReference, (short)0, comFile, cvcaRootIndex, (short)rootCertHolderReference.length);
                    Util.arrayCopy(altCertHolderReference, (short)0, comFile, cvcaAltIndex, (short)altCertHolderReference.length);
                    currentCertPublicKey.getExponent(rootCertPublicKeyData, (short)0);
                    currentCertPublicKey.getModulus(rootCertPublicKeyData, (short)3);
                }
                if(setTime) {
                    Util.arrayCopy(currentCertEffDate, (short)0, currentDate, (short)0, (short)6);
                }
                // TODO copy stuff to COM file
                JCSystem.commitTransaction();
            }
            if(setCert) {
                clear();
            }
        } else {
            clear();
        }
        return result;
    }

    /**
     * Sets the root certificate data
     * 
     * @param in root certificate data array
     */
    void setRootCertificate(byte[] in) {
        if(rootCertHolderReference != null) {
            // The root certificate is already initialized
            return;
        }
        short certHolderReferenceOffset = data[OFFSET_SUB_ID_OFFSET];
        short certHolderReferenceLength = data[OFFSET_SUB_ID_LENGTH];
        short pubKeyExpOffset = data[OFFSET_PUB_KEY_EXPONENT_OFFSET];
        short pubKeyExpLength = data[OFFSET_PUB_KEY_EXPONENT_LENGTH];
        short pubKeyModOffset = data[OFFSET_PUB_KEY_MODULUS_OFFSET];
        short pubKeyModLength = data[OFFSET_PUB_KEY_MODULUS_LENGTH];
        short authorizationOffset = data[OFFSET_AUTHORIZATION_OFFSET];
        short effDateOffset = data[OFFSET_EFF_DATE_OFFSET];
        short expDateOffset = data[OFFSET_EXP_DATE_OFFSET];
        rootCertHolderReference = new byte[17];
        altCertHolderReference = new byte[17];
        Util.arrayCopyNonAtomic(in, certHolderReferenceOffset, rootCertHolderReference, (short)1, certHolderReferenceLength);
        rootCertHolderReference[0] = (byte)certHolderReferenceLength;
        rootCertPublicKeyData = new byte[(short)(pubKeyExpLength + pubKeyModLength)];
        altCertPublicKeyData = new byte[(short)(pubKeyExpLength + pubKeyModLength)];
        Util.arrayCopyNonAtomic(in, pubKeyExpOffset, rootCertPublicKeyData, (short)0, pubKeyExpLength);
        Util.arrayCopyNonAtomic(in, pubKeyModOffset, rootCertPublicKeyData, pubKeyExpLength, pubKeyModLength);
        rootCertAuthorization = new byte[4]; 
        altCertAuthorization = new byte[4];
        Util.arrayCopyNonAtomic(in, authorizationOffset, rootCertAuthorization, (short)0, (short)4);
        rootCertEffDate = new byte[6];
        altCertEffDate = new byte[6];
        Util.arrayCopyNonAtomic(in, effDateOffset, rootCertEffDate, (short)0, (short)6);
        rootCertExpDate = new byte[6];
        altCertExpDate = new byte[6];
        Util.arrayCopyNonAtomic(in, expDateOffset, rootCertExpDate, (short)0, (short)6);
        clear();
    }

    /**
     * Parse the current certificate. The data in source/in is analyzed and
     * offsets and lengths of particular elements of the certificate are stored
     * in the data array. For the root certificate (root == true) we do not
     * parse the signature (we have chosen not to provide it). The format of the
     * certificate is described in ISO18013-3, Section C.2.
     * 
     * @param in
     *            the array with the certificate to be parsed
     * @param offset
     *            offset to in
     * @param length
     *            length of the data
     * @param root
     *            whether we are parsing a root certificate
     */
    void parseCertificate(byte[] in, short offset, short length, boolean root) {
        try {
            offset = BERTLVScanner.readTag(in, offset);
            if (BERTLVScanner.tag != TAG_CERT_BODY) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset = BERTLVScanner.readLength(in, offset);

            offset = BERTLVScanner.readTag(in, offset);
            offset = BERTLVScanner.readLength(in, offset);
            if (BERTLVScanner.tag != TAG_CERT_VERSION
                    || BERTLVScanner.valueLength != (short) 1
                    || in[offset] != (byte) 0x00) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset = BERTLVScanner.skipValue();

            offset = BERTLVScanner.readTag(in, offset);
            if (BERTLVScanner.tag != TAG_AUTH_ID) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            BERTLVScanner.readLength(in, offset);
            offset = BERTLVScanner.skipValue();

            offset = BERTLVScanner.readTag(in, offset);
            if (BERTLVScanner.tag != TAG_PUB_KEY) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset = BERTLVScanner.readLength(in, offset);

            offset = BERTLVScanner.readTag(in, offset);
            offset = BERTLVScanner.readLength(in, offset);
            if (BERTLVScanner.tag != TAG_OID
                    || BERTLVScanner.valueLength != (short) 7
                    || Util.arrayCompare(in, offset, RSA_SHA1_OID, (short) 0,
                            (short) 7) != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset = BERTLVScanner.skipValue();

            offset = BERTLVScanner.readTag(in, offset);
            if (BERTLVScanner.tag != TAG_MODULUS) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            data[OFFSET_PUB_KEY_MODULUS_OFFSET] = BERTLVScanner.readLength(in,
                    offset);
            data[OFFSET_PUB_KEY_MODULUS_LENGTH] = BERTLVScanner.valueLength;
            offset = BERTLVScanner.skipValue();
            if (in[data[OFFSET_PUB_KEY_MODULUS_OFFSET]] == (byte) 0x00) {
                data[OFFSET_PUB_KEY_MODULUS_OFFSET]++;
                data[OFFSET_PUB_KEY_MODULUS_LENGTH]--;
            }

            offset = BERTLVScanner.readTag(in, offset);
            if (BERTLVScanner.tag != TAG_EXPONENT) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            data[OFFSET_PUB_KEY_EXPONENT_OFFSET] = BERTLVScanner.readLength(in,
                    offset);
            data[OFFSET_PUB_KEY_EXPONENT_LENGTH] = BERTLVScanner.valueLength;
            offset = BERTLVScanner.skipValue();
            if (in[data[OFFSET_PUB_KEY_EXPONENT_OFFSET]] == (byte) 0x00) {
                data[OFFSET_PUB_KEY_EXPONENT_OFFSET]++;
                data[OFFSET_PUB_KEY_EXPONENT_LENGTH]--;
            }

            offset = BERTLVScanner.readTag(in, offset);
            if (BERTLVScanner.tag != TAG_SUBJECT_ID) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            data[OFFSET_SUB_ID_OFFSET] = BERTLVScanner.readLength(in, offset);
            data[OFFSET_SUB_ID_LENGTH] = BERTLVScanner.valueLength;
            offset = BERTLVScanner.skipValue();

            offset = BERTLVScanner.readTag(in, offset);
            offset = BERTLVScanner.readLength(in, offset);
            if (BERTLVScanner.tag != TAG_SUBJECT_AUTH
                    || BERTLVScanner.valueLength != (short) 15) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset = BERTLVScanner.readTag(in, offset);
            offset = BERTLVScanner.readLength(in, offset);
            if (BERTLVScanner.tag != TAG_OID
                    || BERTLVScanner.valueLength != (short) 7
                    || Util.arrayCompare(in, offset, AR_TERMINAL_OID,
                            (short) 0, (short) 7) != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset = BERTLVScanner.skipValue();

            offset = BERTLVScanner.readTag(in, offset);
            data[OFFSET_AUTHORIZATION_OFFSET] = BERTLVScanner.readLength(in,
                    offset);
            if (BERTLVScanner.tag != TAG_AUTHORIZATION
                    || BERTLVScanner.valueLength != (short) 4) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset = BERTLVScanner.skipValue();

            offset = BERTLVScanner.readTag(in, offset);
            data[OFFSET_EFF_DATE_OFFSET] = BERTLVScanner.readLength(in, offset);
            if (BERTLVScanner.tag != TAG_EFF_DATE
                    || BERTLVScanner.valueLength != (short) 6) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset = BERTLVScanner.skipValue();

            offset = BERTLVScanner.readTag(in, offset);
            data[OFFSET_EXP_DATE_OFFSET] = BERTLVScanner.readLength(in, offset);
            if (BERTLVScanner.tag != TAG_EXP_DATE
                    || BERTLVScanner.valueLength != (short) 6) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            offset = BERTLVScanner.skipValue();
            data[OFFSET_BODY_LENGTH] = offset;
            if (!root) {
                offset = BERTLVScanner.readTag(in, offset);
                if (BERTLVScanner.tag != TAG_SIGNATURE) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                data[OFFSET_SIGNATURE_OFFSET] = BERTLVScanner.readLength(in,
                        offset);
                data[OFFSET_SIGNATURE_LENGTH] = BERTLVScanner.valueLength;
                source[0] = in;
            }
        } catch (Exception e) {
            clear();
            ISOException.throwIt((short) (ISO7816.SW_WRONG_DATA));
        }

    }

    boolean subjectIdSelected() {
        return currentCertSubjectId[0] != 0;
    }
    
    void selectRootHolderReference() throws ISOException {
        // This should never fail:
        if(!selectSubjectId(rootCertHolderReference, (short)1, (short)(rootCertHolderReference.length - 1))) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
    
    RSAPublicKey getPublicKey() {
        return currentCertPublicKey;
    }
    
    byte[] getAuthorization() {
        return effectiveCertAuthorization;
    }
    
    /**
     * Compares two dates.
     * 
     * @param date1
     *            the first date
     * @param offset1
     *            offset to the first date
     * @param date2
     *            the second date
     * @param offset2
     *            offset to the second date
     * @return -1 if the first date is before the second, 1 if it is after, 0 if
     *         the same
     */
    private byte compareDate(byte[] date1, short offset1, byte[] date2,
            short offset2) {
        short year1 = (short) ((short) (date1[offset1] * 10) + date1[(short) (offset1 + 1)]);
        short year2 = (short) ((short) (date2[offset2] * 10) + date2[(short) (offset2 + 1)]);
        short month1 = (short) ((short) (date1[(short) (offset1 + 2)] * 10) + date1[(short) (offset1 + 3)]);
        short month2 = (short) ((short) (date2[(short) (offset2 + 2)] * 10) + date2[(short) (offset2 + 3)]);
        short day1 = (short) ((short) (date1[(short) (offset1 + 4)] * 10) + date1[(short) (offset1 + 5)]);
        short day2 = (short) ((short) (date2[(short) (offset2 + 4)] * 10) + date2[(short) (offset2 + 5)]);
        if (year1 < year2) {
            return -1;
        } else if (year1 > year2) {
            return 1;
        }
        if (month1 < month2) {
            return -1;
        } else if (month1 > month2) {
            return 1;
        }
        if (day1 < day2) {
            return -1;
        } else if (day1 > day2) {
            return 1;
        }
        return 0;
    }
    
    // Normally this would be arrayFillNonAtomic, but this needs to 
    // undergo a transaction treatment
    private static void cleanArray(byte[] array) {
        for(short i = 0; i<array.length; i++) {
            array[i] = (byte)0;
        }
    }

    // Same here
    private static void cleanArray(short[] array) {
        for(short i = 0; i<array.length; i++) {
            array[i] = (short)0;
        }
    }

    void setCOMFileData(byte[] file, short cvcaRootIndex, short cvcaAltIndex) {
        this.comFile = file;
        this.cvcaRootIndex = cvcaRootIndex;
        this.cvcaAltIndex = cvcaAltIndex;
    }
}
