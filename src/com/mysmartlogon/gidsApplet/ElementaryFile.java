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

/**
 * \brief The abstract class ElementaryFile.
 *
 * It's main purpose is to be able to easily differentiate between EFs and DFs.
 */
public abstract class ElementaryFile extends File {
    private byte shortFileID;

    /**
     * \brief Abstract constructor to be called by subclasses.
     *
     * \param fileControlInformation The array of bytes containing the valid (!) File Control Information.
     *									No Copy is made.
     *
     * \param fileID The ID of the file. Consistency with tag 0x83 from the FCI is NOT checked.
     *
     * \attention No copy of the FCI is made. Do not pass any buffer that is altered
     *				later (e.g. the apdu buffer). Max length 257 bytes as the length
     *				of the FCI Tag (6F) must be a byte.
     *
     * \attention To be safe, use IsoFileSystem.getSafeFile() to instantiate files.
     */
    public ElementaryFile(short fileID, byte[] fileControlInformation) {
        super(fileID, fileControlInformation);
        // If not specified otherwise, the SFI should be the last 5 bits of the FID.
        this.shortFileID = (byte) (fileID & 0x001F);
    }

    /**
     * \brief Get the short file Identifier (SFI).
     *
     * \return The SFI.
     */
    public byte getShortFileID() {
        return shortFileID;
    }

}
