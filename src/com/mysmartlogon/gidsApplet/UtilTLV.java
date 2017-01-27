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

import javacard.framework.Util;

/**
 * \brief Utility class for TLV-realted operations.
 */
public class UtilTLV {

    /** \brief Find the position of the tag at level 1.
     *
     * \attention This method only searches level 1 of TLV encoded arrays (i.e. no nested TLVs are searched).
     *
     * \param tlv The array containing the TLV-encoded object to search.
     *
     * \param tlvOffset The position at which the TLV structure begins.
     *
     * \param tlvLength The length of the TLV structure.
     *
     * \param tag The tag to search for.
     *
     * \return The position of the tag.
     *
     * \throw NotFoundException If the tag could not be found.
     *
     * \throw InvalidArgumentsException Malformatted TLV data.
     */
    public static short findTag(byte[] tlv, short tlvOffset, short tlvLength, byte tag) throws NotFoundException, InvalidArgumentsException {
        short tagPos = tlvOffset;
        short len;

        while(tagPos < (short)(tlvLength+tlvOffset-1)) {
            if(tlv[tagPos] == tag) {
                return tagPos;
            }
            len = decodeLengthField(tlv, (short)(tagPos+1));
            // Increase the position by: T length (1), L length, V length.
            // I.e. look at the next Tag, jump over current L and V field.
            // This saves execution time and ensures that no byte from V is misinterpreted.
            tagPos += 1 + getLengthFieldLength(tlv, (short)(tagPos+1)) + len;
        }
        throw NotFoundException.getInstance();
    }

    /**
     * \brief Check the consistency of the TLV structure.
     *
     * Basically, we jump from one tag to the next. At the end, we must be at the position
     * where the next tag would be, if it was there. If the position is any other than that,
     * the TLV structure is not consistent.
     *
     * \param tlv The array containing the TLV-encoded object to search.
     *
     * \param offset The position at which the TLV structure begins.
     *
     * \param length The length of the TLV structure.
     *
     * \return True if the TLV structure is valid, else false.
     */
    public static boolean isTLVconsistent(byte[] tlv, short offset, short length) {
        short pos = offset;
        short len;

        while(pos < (short)(length+offset-1)) {
            try {
                len = decodeLengthField(tlv, (short)(pos+1));
                pos += 1 + getLengthFieldLength(tlv, (short)(pos+1)) + len;
            } catch (InvalidArgumentsException e) {
                return false;
            }
        }
        return (pos == (short)(offset+length));
    }

    /**
     * \brief Decode the length field of a TLV-entry.
     *
     * The length field itself can be 1, 2 or 3 bytes long:
     * 	- If the length is between 0 and 127, it is 1 byte long.
     * 	- If the length is between 128 and 255, it is 2 bytes long.
     *		The first byte is 0x81 to indicate this.
     *	- If the length is between 256 and 65535, it is 3 bytes long.
     *		The first byte is 0x82, the following 2 contain the actual length.
     *		Note: Only lengths up to 0x7FFF (32767) are supported here, because a short in Java is signed.
     *
     * \param buf The buffer containing the length field.
     *
     * \param offset The offset at where the length field starts.
     *
     * \param length The length of the buffer (buf). This is to prevent that the index gets out of bounds.
     *
     * \return The (positive) length encoded by the length field, or in case of an error, -1.
     *
     * \throw InvalidArgumentsException If offset is too big for a signed Java short
     *                                  If the first byte of the length field is invalid
     */
    public static short decodeLengthField(byte[] buf, short offset) throws InvalidArgumentsException {
        if(buf[offset] == (byte)0x82) { // 256..65535
            // Check for short overflow
            // (In Java, a short is signed: positive values are 0000..7FFF)
            if(buf[(short)(offset+1)] < 0) { // 80..FF
                throw InvalidArgumentsException.getInstance();
            }
            return Util.getShort(buf, (short)(offset+1));
        } else if(buf[offset] == (byte)0x81) {
            return (short) ( 0x00FF & buf[(short)(offset+1)]);
        } else if(buf[offset] > 0) { // 00..7F
            return (short) ( 0x007F & buf[offset]);
        } else {
            throw InvalidArgumentsException.getInstance();
        }
    }

    /**
     * \brief Get the length of the length field of a TLV-entry.
     *
     * \attention Not the length of the value-field is returned,
     * but the length of the length field itself.
     *
     * \see decodeLengthField()
     *
     * \param length The decoded length from the TLV-entry.
     *
     * \return The length of the length field.
     *
     * \throw InvalidArgumentsException If the length would overflow the signed
     *                                  short of Java.
     */
    public static short getLengthFieldLength(byte[] buf, short offset) {
        if(buf[offset] == (byte)0x82) { // 256..65535
            // Check for short overflow
            // (In Java, a short is signed: positive values are 0000..7FFF)
            return (short)3;
        } else if(buf[offset] == (byte)0x81) {
            return (short)2;
        } else {
            return (short)1;
        }
    }

    /**
     * \brief Get the length of the length field of a TLV-entry.
     *
     * \attention Not the length of the value-field is returned,
     * but the length of the length field itself.
     *
     * \see decodeLengthField()
     *
     * \param length The decoded length from the TLV-entry.
     *
     * \return The length of the length field.
     *
     * \throw InvalidArgumentsException If the length would overflow the signed
     *                                  short of Java.
     */
    public static short getEncodingLengthFieldLength(short length) throws InvalidArgumentsException {
        if(length < 0) {
            throw InvalidArgumentsException.getInstance();
        } else if(length < 128) {
            return 1;
        } else if(length < 256) {
            return 2;
        } else {
            return 3;
        }
    }

    /* returns 0 or the size of the BERTLV structure */
    public static short CheckBERTLV(byte[] buf, short offset, short len) {
        short size = 0;
        short sizeforsize = 0;
        short i = 1;
        short totalsize = 0;

        if ((buf[offset] & 0x1F) != 0x1F) {
            // simplified tag
        } else {
            // tag start with all 5 last bits to 1
            // skip the tag
            while (((buf[(short) (offset + i)] & 0x80) != 0) && i < len) {
                i++;
            }
            // pass the last byte of the tag
            i+=1;
        }
        if ((short) (i+1) >len) {
            return 0;
        }
        // check the size
        if ((buf[(short) (offset + i)] & 0x80) != 0) {
            // size encoded in many bytes
            sizeforsize = (short) (buf[(short) (offset + i)] & 0x7F);
            if ((short) (i+1+sizeforsize) >len) {
                return 0;
            }
            if (sizeforsize > (short) 2) {
                // more than two bytes for encoding => not something than we can handle
                return 0;
            } else if (sizeforsize == (short) 1) {
                if ((short) (offset + i + 1 + sizeforsize) > len) {
                    return 0;
                }
                size = Util.makeShort((byte) 0,buf[(short) (offset + i + 1)]);
            } else if (sizeforsize == 2) {
                totalsize = (short) (i + 1 + sizeforsize + size);
                if ((short) (offset + i + 1 + sizeforsize) > len) {
                    return (short) 0;
                }
                size = Util.getShort(buf, (short) (offset + i + 1));
            }
        } else {
            // size encode in one byte
            size = Util.makeShort((byte) 0,buf[(short) (offset + i)]);
        }
        totalsize = (short) (i + 1 + sizeforsize + size);
        if (totalsize < (short) 240 && (short) (offset +  totalsize) > len) {
            return (short) 0;
        }
        return totalsize;
    }


    public static boolean IsBERTLVTagEqual(byte[] tag, short offset, short length, byte[] value) {
        short i = 1;
        // first byte contains the class description
        if (tag[offset] != value[(short)0]) {
            return false;
        }
        // simplified tag
        if ((value[(short) 0] & 0x1F ) != 0x1F) {
            return true;
        }
        // subsequent bytes starts by 1xxxxxxx until the last byte 0xxxxxxx
        while(((short) (offset + i) < length) && (tag[(short) (offset+i)] == value[i]) && ((value[i] & 0x80) != 0)) {
            i++;
        }
        // check if the loop stopped because of 0xxxxxxx or an error
        if (((short) (offset + i + 1) <= length) && (tag[(short) (offset+i)] == value[i])) {
            return true;
        }
        return false;
    }

    /* input data is supposed to have been validaded before */
    public static short GetBERTLVDataLen(byte[] buf, short offset, short len) {
        short size = 0;
        short sizeforsize = 0;
        short i = 1;

        if ((buf[offset] & 0x1F) != 0x1F) {
            // simplified tag
        } else {
            // tag start with all 5 last bits to 1
            // skip the tag
            while (((buf[(short) (offset + i)] & 0x80) != 0) && ((short)(i+offset)) < len) {
                i++;
            }
            // pass the last byte of the tag
            i+=1;
        }
        // check the size
        if ((buf[(short) (offset + i)] & 0x80) != 0) {
            // size encoded in many bytes
            sizeforsize = (short) (buf[(short) (offset + i)] & 0x7F);
            if (sizeforsize > 2) {
                // more than two bytes for encoding => not something than we can handle
                return 0;
            } else if (sizeforsize == 1) {
                size = Util.makeShort((byte) 0,buf[(short) (offset + i + 1)]);
            } else if (sizeforsize == 2) {
                size = Util.getShort(buf, (short) (offset + i + 1));
            }
        } else {
            // size encode in one byte
            size = Util.makeShort((byte) 0,buf[(short) (offset + i)]);
        }
        return size;
    }
}
