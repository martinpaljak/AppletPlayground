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
 * \brief Class used to overwrite the behavior of the select command
 * Indeed if the partial AID of the applet is found on a select command
 * when the applet is already selected, it should work
 *
 **/
public class ApplicationFile extends DedicatedFile {


    byte[] fileControlInformation = null;
    byte[] fileManagementData  = null;
    public ApplicationFile(short fileID, byte[] fileControlParameter, byte[] fileControlInformation, byte[] fileManagementData) {
        super(fileID, fileControlParameter);
        this.fileControlInformation = fileControlInformation;
        this.fileManagementData = fileManagementData;
    }

    /**
     * \brief Check if this is the AID of the application
     *
     * \param name The array containing the name to compare with the file's name.
     *
     * \param offset The offset at where the name begins.
     *
     * \param length The length of the name.
     *
     * \return false if the DF has no name or the names do not match,
     *			true else.
     */
    public boolean isName(byte[] name, short offset, short length) {
        short namePos;
        short aidlen = 0;
        short i;
        // Find the position of the AID tag (4F) in the fci.
        try {
            namePos = UtilTLV.findTag(fileControlInformation, (short)2, fileControlInformation[(short)1], (byte) 0x4F);
        } catch (NotFoundException e) {
            // This DF has no name.
            return false;
        } catch (InvalidArgumentsException e) {
            return false;
        }
        // This ADF has a AID.
        try {
            aidlen = UtilTLV.decodeLengthField(fileControlInformation, (short)(namePos+1));
            if (aidlen < length) {
                // aid len to check is to big to match
                return false;
            }
        } catch (InvalidArgumentsException e) {
            return false;
        }
        // Advance namePos from "tag" to value.
        try {
            namePos += 1 + UtilTLV.getEncodingLengthFieldLength(length);
        } catch(InvalidArgumentsException e) {
            return false;
        }
        // check if the name can be a part of the AID
        for (i = 0; i < (short)(aidlen - length +1); i++) {
            if ((byte)0 == Util.arrayCompare(name, offset, fileControlInformation, (short)(namePos + i), length) ) {
                return true;
            }
        }
        return false;
    }

    public byte[] getFileManagementData() {
        return fileManagementData;
    }

    public byte[] getFileControlInformation() {
        return fileControlInformation;
    }
}
