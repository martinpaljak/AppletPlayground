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

import javacard.framework.*;

/**
 * \brief The DedicatedFile class.
 *
 * A DedicatedFile object acts as a container for objects of any File subclass except the IsoFileSystem class itself.
 * It emulates the ISO "Dedicated File".
 * Children are stored as references. This means that if a File is being altered after it was added as child,
 * the child is effectively altered as well because it is the same object.
 *
 * The initial size of the array storing the references to the children can be set before compilation.
 * This class tries to increase the size until a maximum value. If you do not want that kind of behavior,
 * set CHILDREN_COUNT_MAX to the same value as CHILDREN_COUNT_START.
 */
public class DedicatedFile extends File {
    private static final short CHILDREN_COUNT_START = 10;
    private static final short CHILDREN_COUNT_MAX = 30; // set to max. 16383

    public static final byte SPECIFY_EF = 0x01;
    public static final byte SPECIFY_DF = 0x02;
    public static final byte SPECIFY_ANY = 0x03;

    private byte currentNumChildren;
    private File[] children;


    /**
     * \brief Instantiate a new DedicatedFile.
     *
     * \param fileID The file ID. Should be unique inside the filesystem.
     *
     * \param fileControlInformation The array of bytes containing the valid (!) File Control Information.
     *				It must contain the File ID (Tag 83). No Copy is made.
     *
     * \attention No copy of the fcp is made. Do not pass any buffer that is altered
     *				later (e.g. the apdu buffer). Max length 257 bytes as the length
     *				of the fcp Tag (6F) must be a byte.
     *
     * \attention To be safe, use IsoFilesystem.getSafeFile() to instantiate files.
     *
     * \return The DedicatedFile.
     */
    public DedicatedFile(short fileID, byte[] fileControlInformation) {
        super(fileID, fileControlInformation);
        this.currentNumChildren = 0;
        this.children = new File[CHILDREN_COUNT_START];
    }

    /**
     * \brief Clear the contents of the file.
     *
     * When deleting a DedicatedFile, all children will be lost as well.
     * Their content should be cleared as well.
     */
    void clearContents() {
        short i;

        for(i = 0; i < currentNumChildren; i++) {
            children[i].clearContents();
            children[i] = null;
        }
    }

    /**
     * \brief Check if this is the name of this DedicatedFile.
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
        // Find the position of the DF name tag (84) in the fcp.
        try {
            namePos = UtilTLV.findTag(fcp, (short)2, fcp[(short)1], (byte) 0x84);
        } catch (NotFoundException e) {
            // This DF has no name.
            return false;
        } catch (InvalidArgumentsException e) {
            return false;
        }
        // This DF has a name.
        try {
            if(length != UtilTLV.decodeLengthField(fcp, (short)(namePos+1))) {
                // The names do not have equal length.
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
        return ( (byte)0 == Util.arrayCompare(name, offset, fcp, namePos, length) );
    }

    /**
     * \brief Delete a direct children of this DF.
     *
     * This method requests garbage collection.
     *
     * \param fileID The file ID of the children to delete.
     *
     * \throw NotFoundException It no children has the given fileID.
     */
    public void deleteChildren(short fileID) throws NotFoundException {
        short childNum = -1;
        short i;

        for(i = 0; i < currentNumChildren; i++) {
            if(fileID == children[i].getFileID()) {
                childNum = i;
                break;
            }
        }

        if(childNum == -1) {
            throw NotFoundException.getInstance();
        }

        if( ! JCSystem.isObjectDeletionSupported()) {
            // Old file will stay as garbage in the EEPROM - at least clear the contents.
            children[childNum].clearContents();
        }

        children[childNum] = null;
        currentNumChildren--; // We have one less children now.

        // Fill up empty field in children array.
        // The last children is one ahead, so it is at currentNumChildren.
        if(childNum < currentNumChildren) {
            children[childNum] = children[currentNumChildren];
        }

        // Clean up the old file object.
        if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
    }

    /**
     * \brief Add a children to this DF.
     *
     * \param children The children to add. May be a DedicatedFile or any non-abstract ElemetaryFile subclass.
     *
     * \throw NotEnoughSpaceException If CHILDREN_COUNT_MAX is reached.
     */
    public void addChildren(File childFile) throws NotEnoughSpaceException {
        // First we have to check for enough space.
        if(currentNumChildren >= (short)children.length) {
            File[] newChildren = null;
            // The array is full - we try to increase the size.
            if((short)(children.length * 2) <= CHILDREN_COUNT_MAX) {
                // Doubling the size is possible.
                newChildren = new File[(short)(children.length * 2)];
                copyFileArrayRefs(children, newChildren);
            } else {
                // Doubling not possible - try to at least increase to CHILDREN_COUNT_MAX.
                if(currentNumChildren < CHILDREN_COUNT_MAX) {
                    newChildren = new File[CHILDREN_COUNT_MAX];
                    copyFileArrayRefs(children, newChildren);
                } else {
                    // CHILDREN_COUNT_MAX exceeded. No "space" left. Fail.
                    throw NotEnoughSpaceException.getInstance();
                }
            }
            children = newChildren; // Initial children array is now garbage.
            if(JCSystem.isObjectDeletionSupported()) {
                JCSystem.requestObjectDeletion();
            }
        } // We have enough space (now).
        children[currentNumChildren++] = childFile;
        return;
    }

    /**
     * \brief Copies the references from one File array to the other.
     *
     * \attention Although only references are copied, this is probably still quite expensive because
     * writing to the EEPROM is. Only use this for operations that are not called often (Creating and deleting files etc.).
     *
     * \param src The source File array to copy from.
     *
     * \param dest The destination File array to copy to. It MUST be at least of size of the src array.
     */
    private static void copyFileArrayRefs(File[] src, File[] dest) {
        short i = 0;
        short length = src.length > dest.length ? (short)dest.length : (short)src.length;

        for(i=0; i < length; i++) {
            dest[i] = src[i];
        }
        return;
    }


    /**
     * \brief Recursively search the children of this file using the DedicatedFile name.
     *
     * \param name The DF name of at most 16 bytes according to ISO.
     *
     * \param nameOffset The position in the name array at which the name beigns.
     *
     * \param nameLength The length of the name
     *
     * \throw NotFoundException If the specified file was not found among all (sub-)children of this file.
     *
     * \return A reference to the DedicatedFile if found.
     */
    public DedicatedFile findDedicatedFileByNameRec(byte[] name, short nameOffset, short nameLength) throws NotFoundException {
        short i;
        for(i=0; i < currentNumChildren; i++) {
            if(children[i] instanceof DedicatedFile) {
                if(((DedicatedFile)children[i]).isName(name, nameOffset, nameLength)) {
                    return (DedicatedFile) children[i];
                }
                try {
                    return ((DedicatedFile)children[i]).findDedicatedFileByNameRec(name, nameOffset, nameLength);
                } catch(NotFoundException e) {
                    // Ignore this exception until the last children has unsuccessfully been visited.
                }
            }
        }
        throw NotFoundException.getInstance();
    }

    /**
     * \brief Recursively search the children of this file using the file ID.
     *
     * \param fileID The file ID of the file to search for.
     *
     * \throw NotFoundException If the specified file was not found among all (sub-)children of this file.
     *
     * \return A reference to the File if found.
     */
    public File findChildrenRec(short fileID, byte flag) throws NotFoundException {
        short i;
        for(i=0; i < currentNumChildren; i++) {
            if(children[i].getFileID() == fileID) {
                if((flag == SPECIFY_ANY)
                        || (flag == SPECIFY_DF && children[i] instanceof DedicatedFile)
                        || (flag == SPECIFY_EF && children[i] instanceof ElementaryFile)) {
                    return children[i];
                } else {
                    // File with specified FID and requested file type do not match.
                    throw NotFoundException.getInstance();
                }
            }
            if(children[i] instanceof DedicatedFile) {
                try {
                    return ((DedicatedFile)children[i]).findChildrenRec(fileID, flag);
                } catch(NotFoundException e) {
                    // Ignore this exception until the last children has unsuccessfully been visited.
                }
            }
        }
        throw NotFoundException.getInstance();
    }
}











