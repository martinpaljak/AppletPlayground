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
 * $Id: PassportCrypto.java 945 2009-05-12 08:31:57Z woj76 $
 */

package sos.passportapplet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class PassportCrypto {
    public static final byte ENC_MODE = 1;
    public static final byte MAC_MODE = 2;

    public static final byte CREF_MODE = 3;
    public static final byte PERFECTWORLD_MODE = 4;
    public static final byte JCOP41_MODE = 5;
    
    public static final byte INPUT_IS_NOT_PADDED = 5;
    public static final byte INPUT_IS_PADDED = 6;

    public static final byte PAD_INPUT = 7;
    public static final byte DONT_PAD_INPUT = 8;

    MessageDigest shaDigest;
    Signature sig;
    Cipher ciph;
    Cipher rsaCiph;
    KeyStore keyStore;

    Signature rsaSig;
    KeyAgreement keyAgreement;
    boolean[] eacChangeKeys;
//    byte[] eacTerminalKeyHash;
    private static final short EC_X_LENGTH = (short)((short)(KeyBuilder.LENGTH_EC_F2M_163 / 8)+1); 

    public static byte[] PAD_DATA = { (byte) 0x80, 0, 0, 0, 0, 0, 0, 0 };

    protected void init() {
        sig = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3,
                                    false);            
        ciph = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        
    }
    
    public PassportCrypto(KeyStore keyStore) {
        this.keyStore = keyStore;

        init();
        
        shaDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        rsaCiph = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH,
                false);
        eacChangeKeys = JCSystem.makeTransientBooleanArray((short) 1,
                JCSystem.CLEAR_ON_DESELECT);

    }

    public void createMacFinal(byte[] msg, short msg_offset, short msg_len,
            byte[] mac, short mac_offset) {
        sig.sign(msg, msg_offset, msg_len, mac, mac_offset);
    }

    public boolean verifyMacFinal(byte[] msg, short msg_offset, short msg_len,
            byte[] mac, short mac_offset) {
        return sig.verify(msg, msg_offset, msg_len, mac, mac_offset, (short) 8);
    }

    public void decryptInit() {
        DESKey k = keyStore.getCryptKey();
        ciph.init(k, Cipher.MODE_DECRYPT);
    }
    
    public short decrypt(byte[] ctext, short ctext_offset, short ctext_len,
            byte[] ptext, short ptext_offset) {
        return ciph.update(ctext, ctext_offset, ctext_len, ptext, ptext_offset);
    }

    public short decryptFinal(byte[] ctext, short ctext_offset, short ctext_len,
            byte[] ptext, short ptext_offset) {
        return ciph.doFinal(ctext, ctext_offset, ctext_len, ptext, ptext_offset);
    }

    public short encryptInit() {
        return encryptInit(DONT_PAD_INPUT, null, (short)0, (short)0);
    }
    
    public short encryptInit(byte padding, byte[] ptext, short ptext_offset, short ptext_len) {
        DESKey k = keyStore.getCryptKey();
        short newlen=ptext_len;
        if(padding == PAD_INPUT) {
            // pad input
            newlen = PassportUtil.pad(ptext, ptext_offset, ptext_len);
        }
 
        ciph.init(k, Cipher.MODE_ENCRYPT);
        return newlen;
    }
    
    public short encrypt(byte[] ptext,  short ptext_offset, short ptext_len,
            byte[] ctext, short ctext_offset) {
        return ciph.update(ptext, ptext_offset, ptext_len, ctext, ctext_offset);
    }
    
    public short encryptFinal(byte[] ptext,  short ptext_offset, short ptext_len,
            byte[] ctext, short ctext_offset) {
        return ciph.doFinal(ptext, ptext_offset, ptext_len, ctext, ctext_offset);
    }

    public void updateMac(byte[] msg, short msg_offset, short msg_len) {
        sig.update(msg, msg_offset, msg_len);
    }

    public void initMac(byte mode) {
        DESKey k = keyStore.getMacKey();
        
        sig.init(k, mode);    
    }

//    public short unwrapCommandAPDU_werkt(byte[] ssc, APDU aapdu) {
//        byte[] apdu = aapdu.getBuffer();
//        short apdu_p = (short) (ISO7816.OFFSET_CDATA & 0xff);
//        // offset
//        short lc = (short) (apdu[ISO7816.OFFSET_LC] & 0xff);
//        short le = 0;
//        short do87DataLen = 0;
//        short do87Data_p = 0;
//        short do87LenBytes = 0;
//        short hdrLen = 4;
//        short hdrPadLen = (short) (8 - hdrLen);
//        short apduLength = (short) (hdrLen + 1 + lc);
//
//        aapdu.setIncomingAndReceive();
//
//        // sanity check
//        if (apdu.length < (short) (apduLength + hdrPadLen + ssc.length)) {
//            ISOException.throwIt((short)0x6d66);
//        }
//
//        // pad the header, make room for ssc, so we don't have to
//        // modify pointers to locations in the apdu later.
//        Util.arrayCopy(apdu, (short) (hdrLen + 1), // toss away lc
//                       apdu, (short) (hdrLen + hdrPadLen), lc);
//        Util.arrayCopy(PassportCrypto.PAD_DATA,
//                       (short) 0,
//                       apdu,
//                       hdrLen,
//                       hdrPadLen);
//        apduLength--;
//        apduLength += hdrPadLen;
//
//        // add ssc in front (needed to calculate the mac) so we don't have to
//        // modify pointers to locations in the apdu later.
//        incrementSSC(ssc);
//        Util.arrayCopy(apdu, (short) 0, apdu, (short) ssc.length, apduLength);
//        Util.arrayCopy(ssc, (short) 0, apdu, (short) 0, (short) ssc.length);
//
//        apdu_p = (short) (hdrLen + hdrPadLen);
//        apdu_p += (short) ssc.length;
//
//        if (apdu[apdu_p] == (byte) 0x87) {
//            apdu_p++;
//            // do87
//            if ((apdu[apdu_p] & 0xff) > 0x80) {
//                do87LenBytes = (short) (apdu[apdu_p] & 0x7f);
//                apdu_p++;
//            } else {
//                do87LenBytes = 1;
//            }
//            if (do87LenBytes > 2) { // sanity check
//                ISOException.throwIt((short) 0x6d66);
//            }
//            for (short i = 0; i < do87LenBytes; i++) {
//                do87DataLen += (short) ((apdu[(short)(apdu_p + i)] & 0xff) << (short) ((do87LenBytes - 1 - i) * 8));
//            }
//            apdu_p += do87LenBytes;
//
//            if (apdu[apdu_p] != 1) {
//                ISOException.throwIt((short) (0x6d66));
//            }
//            // store pointer to data and defer decrypt to after mac check (do8e)
//            do87Data_p = (short) (apdu_p + 1);
//            apdu_p += do87DataLen;
//            do87DataLen--; // compensate for 0x01 marker
//        }
//
//        if (apdu[apdu_p] == (byte) 0x97) {
//            // do97
//            if (apdu[++apdu_p] != 1)
//                ISOException.throwIt((short) (0x6d66));
//            le = (short) (apdu[++apdu_p] & 0xff);
//            apdu_p++;
//        }
//
//        // do8e
//        if (apdu[apdu_p] != (byte) 0x8e) {
//            ISOException.throwIt((short) (0x6d66));
//        }
//        if (apdu[++apdu_p] != 8) {
//            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//        }
//        
//        initMac();
//        if (!verifyMacFinal(apdu,
//                       (short) 0,
//                       (short) (apdu_p - 1),
//                       apdu,
//                       (short)(apdu_p + 1))) {
//            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
//        }
//
//        // construct unprotected apdu
//        // copy back the hdr
//        Util.arrayCopy(apdu, (short) ssc.length, apdu, (short) 0, hdrLen);
//        apduLength -= 4;
//
//        short plaintextLength = 0;
//        short plaintextLc = 0;
//        if (do87DataLen != 0) {
//            // decrypt data, and leave room for lc
//            decryptInit();
//            plaintextLength = decryptFinal(apdu,
//                                      do87Data_p,
//                                      do87DataLen,
//                                      apdu,
//                                      (short) (hdrLen + 1));
//
//            plaintextLc = PassportUtil.calcLcFromPaddedData(apdu,
//                                                            (short) (hdrLen + 1),
//                                                            do87DataLen);
//            apdu[hdrLen] = (byte) (plaintextLc & 0xff);
//        }
//
//        apduLength = (short) (hdrLen + 1 + plaintextLength);
//
//        // empty out the rest
//        for (short i = apduLength; i < apdu.length; i++) {
//            apdu[i] = 0;
//        }
//
//        return le;
//    }

    public short unwrapCommandAPDU(byte[] ssc, APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short apdu_p = (short) (ISO7816.OFFSET_CDATA & 0xff);
        short start_p = apdu_p;
        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xff);
        short le = 0;
        short do87DataLen = 0;
        short do87Data_p = 0;
        short do87LenBytes = 0;
        short hdrLen = 4;
        short hdrPadLen = (short) (8 - hdrLen);

        apdu.setIncomingAndReceive();

        incrementSSC(ssc);

        if (buf[apdu_p] == (byte) 0x87) {
            apdu_p++;
            // do87
            if ((buf[apdu_p] & 0xff) > 0x80) {
                do87LenBytes = (short) (buf[apdu_p] & 0x7f);
                apdu_p++;
            } else {
                do87LenBytes = 1;
            }
            if (do87LenBytes > 2) { // sanity check
                ISOException.throwIt(PassportApplet.SW_INTERNAL_ERROR);
            }
            for (short i = 0; i < do87LenBytes; i++) {
                do87DataLen += (short) ((buf[(short)(apdu_p + i)] & 0xff) << (short) ((do87LenBytes - 1 - i) * 8));
            }
            apdu_p += do87LenBytes;

            if (buf[apdu_p] != 1) {
                ISOException.throwIt(PassportApplet.SW_INTERNAL_ERROR);
            }
            // store pointer to data and defer decrypt to after mac check (do8e)
            do87Data_p = (short) (apdu_p + 1);
            apdu_p += do87DataLen;
            do87DataLen--; // compensate for 0x01 marker
        }

        if (buf[apdu_p] == (byte) 0x97) {
            // do97
            if (buf[++apdu_p] != 1)
                ISOException.throwIt(PassportApplet.SW_INTERNAL_ERROR);
            le = (short) (buf[++apdu_p] & 0xff);
            apdu_p++;
        }

        // do8e
        if (buf[apdu_p] != (byte) 0x8e) {
            ISOException.throwIt(PassportApplet.SW_INTERNAL_ERROR);
        }
        if (buf[++apdu_p] != 8) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // verify mac
        initMac(Signature.MODE_VERIFY);
        updateMac(ssc, (short)0, (short)ssc.length);
        updateMac(buf, (short)0, hdrLen);
        updateMac(PAD_DATA, (short)0, hdrPadLen);
        if (!verifyMacFinal(buf,
                       start_p,
                       (short) (apdu_p - 1 - start_p),
                       buf,
                       (short)(apdu_p + 1))) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short plaintextLength = 0;
        short plaintextLc = 0;
        if (do87DataLen != 0) {
            // decrypt data, and leave room for lc
            decryptInit();
            plaintextLength = decryptFinal(buf,
                                      do87Data_p,
                                      do87DataLen,
                                      buf,
                                      (short) (hdrLen + 1));

            plaintextLc = PassportUtil.calcLcFromPaddedData(buf,
                                                            (short) (hdrLen + 1),
                                                            do87DataLen);
            buf[hdrLen] = (byte) (plaintextLc & 0xff);
        }

        return le;
    }

    /***
     * Space to reserve in buffer when using secure messaging.
     * 
     * @param plaintextLength length of plaintext in which this offset depends.
     * @return
     */
    public short getApduBufferOffset(short plaintextLength) {
        short do87Bytes = 2; // 0x87 len data 0x01
        // smallest multiple of 8 strictly larger than plaintextLen + 1
        // byte is probably the length of the ciphertext (including do87 0x01)
        short do87DataLen = (short) ((((short) (plaintextLength + 8) / 8) * 8) + 1);        
        
        
        if(do87DataLen < 0x80) {
            do87Bytes++;
        }
        else if(do87DataLen <= 0xff) {
            do87Bytes += 2;
        }
        else {
            do87Bytes += (short)(plaintextLength > 0xff ? 2 : 1);
        }
        return do87Bytes;
    }
    
    public short wrapResponseAPDU(byte[] ssc, APDU aapdu, short plaintextOffset, short plaintextLen,
            short sw1sw2) {
        byte[] apdu = aapdu.getBuffer();
        short apdu_p = 0;
        // smallest multiple of 8 strictly larger than plaintextLen
        short do87DataLen = PassportUtil.lengthWithPadding(plaintextLen);
        // for 0x01 marker (indicating padding is used)
        do87DataLen++;
        short do87DataLenBytes = (short)(do87DataLen > 0xff? 2 : 1);
        short do87HeaderBytes = getApduBufferOffset(plaintextLen);
        short do87Bytes = (short)(do87HeaderBytes + do87DataLen - 1); // 0x01 is counted twice 
        boolean hasDo87 = plaintextLen > 0;

        incrementSSC(ssc);

        short ciphertextLength=0;
        short possiblyPaddedPlaintextLength=0;
        if(hasDo87) {
            // put ciphertext in proper position.
            possiblyPaddedPlaintextLength = encryptInit(PAD_INPUT, apdu, plaintextOffset, plaintextLen);
            ciphertextLength = encryptFinal(
                    apdu,
                    plaintextOffset,
                    possiblyPaddedPlaintextLength,
                    apdu,
                    do87HeaderBytes);
        }
        //sanity check
        //note that this check
        //  (possiblyPaddedPlaintextLength != (short)(do87DataLen -1))
        //does not always hold because some algs do the padding in the final, some in the init.
        if (hasDo87 && (((short) (do87DataLen - 1) != ciphertextLength)))
            ISOException.throwIt((short) 0x6d66);
        
        if (hasDo87) {
            // build do87
            apdu[apdu_p++] = (byte) 0x87;
            if(do87DataLen < 0x80) {
                apdu[apdu_p++] = (byte)do87DataLen; 
            } else {
                apdu[apdu_p++] = (byte) (0x80 + do87DataLenBytes);
                for(short i=(short)(do87DataLenBytes-1); i>=0; i--) {
                    apdu[apdu_p++] = (byte) ((do87DataLen >>> (i * 8)) & 0xff);
                }
            }
            apdu[apdu_p++] = 0x01;
        }

        if(hasDo87) {
            apdu_p = do87Bytes;
        }
        
        // build do99
        apdu[apdu_p++] = (byte) 0x99;
        apdu[apdu_p++] = 0x02;
        Util.setShort(apdu, apdu_p, sw1sw2);
        apdu_p += 2;

        // calculate and write mac
        initMac(Signature.MODE_SIGN);
        updateMac(ssc, (short)0, (short)ssc.length);
        createMacFinal(apdu,
                  (short) 0,
                  apdu_p,
                  apdu,
                  (short)(apdu_p+2));

        // write do8e
        apdu[apdu_p++] = (byte) 0x8e;
        apdu[apdu_p++] = 0x08;
        apdu_p += 8; // for mac written earlier
        if (eacChangeKeys[0]) {
            eacChangeKeys[0] = false;
            keyStore.setSecureMessagingKeys(keyStore.tmpKeys, (short) 0,
                    keyStore.tmpKeys, (short) 16);
            Util.arrayFillNonAtomic(keyStore.tmpKeys, (short) 0, (short) 32,
                    (byte) 0x00);
            Util.arrayFillNonAtomic(ssc, (short) 0, (short) ssc.length,
                    (byte) 0x00);
        }

        return apdu_p;
    }

    /**
     * Derives the ENC or MAC key from the keySeed.
     * 
     * @param keySeed
     *            the key seed.
     * @param mode
     *            either <code>ENC_MODE</code> or <code>MAC_MODE</code>.
     * 
     * @return the key.
     */
    static byte[] c = { 0x00, 0x00, 0x00, 0x00 };

    public void deriveKey(byte[] buffer, short keySeed_offset, short keySeed_length, byte mode, short key_offset)
            throws CryptoException {
        // only key_offset is a write pointer
        // sanity checks
        if ((short)buffer.length < (short)((short)(key_offset + keySeed_length) + c.length)) {
            ISOException.throwIt((short)0x6d66);
        }
        if(keySeed_offset > key_offset) {
            ISOException.throwIt((short)0x6d66);
        }

        c[(short)(c.length-1)] = mode;

        // copy seed || c to key_offset
        Util.arrayCopyNonAtomic(buffer, keySeed_offset, buffer, key_offset, keySeed_length);
        Util.arrayCopyNonAtomic(c, (short) 0, buffer, (short)(key_offset + keySeed_length), (short)c.length);

        // compute hash on key_offset (+seed len +c len)
        shaDigest.doFinal(buffer, key_offset, (short)(keySeed_length + c.length), buffer, key_offset);
        shaDigest.reset();

        // parity bits
        for (short i = key_offset; i < (short)(key_offset + PassportApplet.KEY_LENGTH); i++) {
            if (PassportUtil.evenBits(buffer[i]) == 0)
                buffer[i] = (byte) (buffer[i] ^ 1);
        }
    }

    public static void incrementSSC(byte[] ssc) {
        if (ssc == null || ssc.length <= 0)
            return;

        for (short s = (short) (ssc.length - 1); s >= 0; s--) {
            if ((short) ((ssc[s] & 0xff) + 1) > 0xff)
                ssc[s] = 0;
            else {
                ssc[s]++;
                break;
            }
        }
    }

    public static void computeSSC(byte[] rndICC, short rndICC_offset,
            byte[] rndIFD, short rndIFD_offset, byte[] ssc) {
        if (rndICC == null || (short) (rndICC.length - rndICC_offset) < 8
                || rndIFD == null
                || (short) (rndIFD.length - rndIFD_offset) < 8) {
            ISOException.throwIt((short) 0x6d66);
        }

        Util.arrayCopyNonAtomic(rndICC,
                       (short) (rndICC_offset + 4),
                       ssc,
                       (short) 0,
                       (short) 4);
        Util.arrayCopyNonAtomic(rndIFD,
                       (short) (rndIFD_offset + 4),
                       ssc,
                       (short) 4,
                       (short) 4);
    }

    public void createHash(byte[] msg, short msg_offset, short length,
            byte[] dest, short dest_offset) throws CryptoException {
        if ((dest.length < (short) (dest_offset + length))
                || (msg.length < (short) (msg_offset + length)))
            ISOException.throwIt((short) 0x6d66);

        try {
            shaDigest.doFinal(msg, msg_offset, length, dest, dest_offset);
        } finally {
            shaDigest.reset();
        }

    }
    
    /**
     * Chip authentication part of EAP.
     *
     * @param pubData
     *            the other parties public key data
     * @param offset
     *            offset to the public key data
     * @param length
     *            public key data length
     *
     * @return true when authentication successful
     */
    public boolean authenticateChip(byte[] pubData, short offset, short length) {
        try {
            // Verify public key first. i.e. see if the data is correct and
            // makes up a valid
            // EC public key.
            keyStore.ecPublicKey.setW(pubData, offset, length);
            if (!keyStore.ecPublicKey.isInitialized()) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }

            // Do the key agreement and derive new session keys based on the
            // outcome:
            keyAgreement.init(keyStore.ecPrivateKey);
            short secOffset = (short) (offset + length);
            short secLength = keyAgreement.generateSecret(pubData, offset,
                    length, pubData, secOffset);
            // use only first 16 bytes?
            // secLength = 16;
            short keysOffset = (short) (secOffset + secLength);
            deriveKey(pubData, secOffset, secLength, MAC_MODE, keysOffset);
            short macKeyOffset = keysOffset;
            keysOffset += PassportApplet.KEY_LENGTH;
            deriveKey(pubData, secOffset, secLength, ENC_MODE, keysOffset);
            short encKeyOffset = keysOffset;
            Util.arrayCopyNonAtomic(pubData, macKeyOffset, keyStore.tmpKeys,
                    (short) 0, PassportApplet.KEY_LENGTH);
            Util.arrayCopyNonAtomic(pubData, encKeyOffset, keyStore.tmpKeys,
                    PassportApplet.KEY_LENGTH, PassportApplet.KEY_LENGTH);
            // The secure messaging keys should be replaced with the freshly
            // computed ones
            // just after the current APDU is completely processed.
            eacChangeKeys[0] = true;
            return true;
        } catch (Exception e) {
            eacChangeKeys[0] = false;
            return false;
            
        }
    }

    boolean eacVerifySignature(RSAPublicKey key, byte[] rnd, 
            byte[] docNr, byte[] buffer, short offset, short length) {
        short x_offset = (short)(offset+length);
        keyStore.ecPublicKey.getW(buffer, x_offset++);
        rsaSig.init(key, Signature.MODE_VERIFY);
        rsaSig.update(docNr, (short) 0, (short) docNr.length);
        rsaSig.update(rnd, (short) 0, PassportApplet.RND_LENGTH);
        return rsaSig.verify(buffer, x_offset, EC_X_LENGTH, buffer, offset, length);
    }


}
