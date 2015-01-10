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
 * $Id$
 */

package sos.passportapplet;

import javacard.framework.ISOException;
import javacard.framework.Util;

/*******************************************************************************
 * Contains methods to initialize a fresh passport.
 * 
 * @author Cees-Bart Breunesse (ceesb@cs.ru.nl)
 * @author Engelbert Hubbers (hubbers@cs.ru.nl)
 * @author Martijn Oostdijk (martijno@cs.ru.nl)
 * 
 */
public class PassportInit {

    private PassportCrypto crypto;

    private static byte[] weights = { 7, 3, 1 };

    PassportInit(PassportCrypto crypto) {
        this.crypto = crypto;
    }
    /**
     * Looks up the numerical value for MRZ characters. In order to be able to
     * compute check digits.
     * 
     * @param ch
     *            a character from the MRZ.
     * @return the numerical value of the character.
     */
    private static byte decodeMRZDigit(byte ch) {
        switch (ch) {
        case '<':
        case '0':
            return 0;
        case '1':
            return 1;
        case '2':
            return 2;
        case '3':
            return 3;
        case '4':
            return 4;
        case '5':
            return 5;
        case '6':
            return 6;
        case '7':
            return 7;
        case '8':
            return 8;
        case '9':
            return 9;
        case 'a':
        case 'A':
            return 10;
        case 'b':
        case 'B':
            return 11;
        case 'c':
        case 'C':
            return 12;
        case 'd':
        case 'D':
            return 13;
        case 'e':
        case 'E':
            return 14;
        case 'f':
        case 'F':
            return 15;
        case 'g':
        case 'G':
            return 16;
        case 'h':
        case 'H':
            return 17;
        case 'i':
        case 'I':
            return 18;
        case 'j':
        case 'J':
            return 19;
        case 'k':
        case 'K':
            return 20;
        case 'l':
        case 'L':
            return 21;
        case 'm':
        case 'M':
            return 22;
        case 'n':
        case 'N':
            return 23;
        case 'o':
        case 'O':
            return 24;
        case 'p':
        case 'P':
            return 25;
        case 'q':
        case 'Q':
            return 26;
        case 'r':
        case 'R':
            return 27;
        case 's':
        case 'S':
            return 28;
        case 't':
        case 'T':
            return 29;
        case 'u':
        case 'U':
            return 30;
        case 'v':
        case 'V':
            return 31;
        case 'w':
        case 'W':
            return 32;
        case 'x':
        case 'X':
            return 33;
        case 'y':
        case 'Y':
            return 34;
        case 'z':
        case 'Z':
            return 35;
        default:
            throw new ISOException((short) 0x6d04);
        }
    }

    /**
     * Computes the 7-3-1 check digit for part of the MRZ.
     * 
     * @param chars
     *            a part of the MRZ.
     * @return the resulting check digit.
     */
    static byte checkDigit(byte[] chars, short offset, short length) {
        byte result = 0;
        for (short i = 0; i < length; i++) {
            result = (byte) ((short) ((result + weights[i % 3]
                    * decodeMRZDigit(chars[(short) (offset + i)]))) % 10);
        }
        return (byte) (result + 0x30); // return as character
    }

    public static short DOCNR_LEN = 9;
    public static short DOB_LEN = 6;
    public static short DOE_LEN = 6;

    /**
     * Computes the static key seed, based on information from the MRZ.
     * 
     * @param buffer
     *            containing docNr || dateOfBirth || dateOfExpiry
     * @param offset
     *            pointing to docNr
     * @returns offset in buffer pointing to keySeed.
     */
    public short computeKeySeed(
        byte[] buffer, 
        short docNr_p,
        short docNr_length,
        short dateOfBirth_p,
        short dateOfBirth_length,
        short dateOfExpiry_p,
        short dateOfExpiry_length) {

        // sanity check: data is ordered
        if(!((docNr_p < dateOfBirth_p) & (dateOfBirth_p < dateOfExpiry_p))) {
            ISOException.throwIt((short)0x6d66);            
        }
        // sanity check: no overlap
        if(((short)(docNr_p + docNr_length) > dateOfBirth_p) ||
           ((short)(dateOfBirth_p + dateOfBirth_length) > dateOfExpiry_p)) {
            ISOException.throwIt((short)0x6d66);               
        }
            
        short buffer_p = 0;
        Util.arrayCopyNonAtomic(buffer, docNr_p, buffer, buffer_p, docNr_length);
        short offset = buffer_p;
        buffer_p += docNr_length;
        buffer[buffer_p] = checkDigit(buffer, offset, docNr_length);
        buffer_p++;
        
        Util.arrayCopyNonAtomic(buffer, dateOfBirth_p, buffer, buffer_p, dateOfBirth_length);
        offset = buffer_p;
        buffer_p += dateOfBirth_length;
        buffer[buffer_p] = checkDigit(buffer, offset, dateOfBirth_length);
        buffer_p++;
        
        Util.arrayCopyNonAtomic(buffer, dateOfExpiry_p, buffer, buffer_p, dateOfExpiry_length);
        offset = buffer_p;
        buffer_p += dateOfExpiry_length;
        buffer[buffer_p] = checkDigit(buffer, offset, dateOfExpiry_length);
        buffer_p++;
        
        crypto.createHash(buffer,
                                  (short)0,
                                  buffer_p,
                                  buffer,
                                  (short)0);
       
        
        return 0;
    }
    /**
     * Computes the static key seed, based on information from the MRZ.
     * 
     * @param buffer
     *            containing docNr || dateOfBirth || dateOfExpiry
     * @param offset
     *            pointing to docNr
     * @returns offset in buffer pointing to keySeed.
     */
    public short computeKeySeed(byte[] buffer, short offset) {
        // sanity checks (80 for hash, 3 for checkdigits)
        if (buffer.length < (short) (offset + DOCNR_LEN + DOB_LEN + DOE_LEN
                + 80 + 3)) {
            ISOException.throwIt((short) 0x6d66);
        }
        short start_offset = offset;
        // offset must initially point to docNr
        offset += DOCNR_LEN;
        short len = (short) (DOB_LEN + DOE_LEN);

        // make room for checkdigit after docNr
        Util.arrayCopyNonAtomic(buffer, offset, buffer, (short) (offset + 1), len);
        buffer[offset] = checkDigit(buffer,
                                    (short) (offset - DOCNR_LEN),
                                    DOCNR_LEN);

        offset += (short) (1 + DOB_LEN);
        len -= DOB_LEN;

        // make room for checkdigit after dateOfBirth
        Util.arrayCopyNonAtomic(buffer, offset, buffer, (short) (offset + 1), len);
        buffer[offset] = checkDigit(buffer, (short) (offset - DOB_LEN), DOB_LEN);

        offset += (short) (1 + DOE_LEN);

        buffer[offset] = checkDigit(buffer, (short) (offset - DOE_LEN), DOE_LEN);

        offset++;

        crypto.createHash(buffer,
                                  start_offset,
                                  (short) (offset - start_offset),
                                  buffer,
                                  offset);

        return offset;
    }
}
