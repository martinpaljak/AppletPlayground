/*
 * Java Card PKI applet - ISO7816 compliant Java Card applet. 
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
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

package net.sourceforge.javacardsign.applet;

import javacard.framework.Util;
import javacard.framework.JCSystem;

/**
 * Encapsulates the file system for the PKI applet.
 * 
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 * 
 */
final class FileSystem {

    final static short MASTER_FILE_ID = (short) 0x3F00;

    final static byte PERM_FREE = 0;

    final static byte PERM_PIN = 1;

    private static final byte DIR = -1;

    private Object[] efFiles = null;

    private byte[] efPerms = null;

    private short totalFiles = 0;

    /** Stores the file structure information for this file system.
     * The initial contents of this array should be following the pattern below,
     * see also the documentation in the pkihostapi library, the PKIPersoService class.
     *
     * The hierarchical structure for the file system in our
     * applet. The data is as follows, concatenated in sequence:
     * 
     * byte 0: -1/0 -1 for DF, 0 for EF
     * byte 1, 2: fid msb, fid lsb
     * byte 3: index to the parent in this array, -1 of root node
     * byte 4: for EF the SFI of this file
     *         for DF number of children nodes, the list of indexes to the
     *         children follow.
     * 
     * When EF files are created the first byte (initially 0) of the
     * according file in this structure is replaced with the index to
     * the {@link #efFiles}, where the reference to the file array
     * is stored.  
     */
    byte[] fileStructure = null;

    private short[] fileStructureIndex;

    FileNotFoundException fnfe;

    /**
     * Create a new file system for maxFiles maximum number of files.
     * 
     * @param maxFiles
     *            the maximum number of files.
     */
    FileSystem(short maxFiles) {
        efFiles = new Object[maxFiles];
        efPerms = new byte[maxFiles];
        fileStructureIndex = JCSystem.makeTransientShortArray((short) 1,
                JCSystem.CLEAR_ON_DESELECT);
        fnfe = new FileNotFoundException();
    }

    /**
     * Create a new file
     * 
     * @param fid
     *            the ID of the file to be create
     * @param length
     *            the file contents length
     * @param perm
     *            the permission byte, see {@link #PERM_FREE},
     *            {@link #PERM_PIN}
     * @return whether the file was successfully created
     */
    boolean createFile(short fid, short length, byte perm) {
        if (totalFiles == efFiles.length) {
            return false;
        }
        try {
            short index = searchId((short) 0, fid);
            efFiles[totalFiles] = new byte[length];
            efPerms[totalFiles] = perm;
            fileStructure[index] = (byte) totalFiles;
            totalFiles++;
            return true;
        } catch (FileNotFoundException e) {
            return false;
        }
    }

    /**
     * Returns the array with the contents of the given file
     * 
     * @param index
     *            the index to the file
     * @return the array with the contents of the file
     */
    byte[] getFile(short index) {
        try {
            return (byte[]) efFiles[index];
        } catch (ArrayIndexOutOfBoundsException aioobe) {
            return null;
        }
    }

    /**
     * Returns the permission byte of the given file
     * 
     * @param index
     *            the index to the file
     * @return the permission byte of the file
     */
    byte getPerm(short index) {
        return efPerms[index];
    }

    /**
     * Get the index to the currently selected file, -1 if none selected.
     * 
     * @return the index to the currently selected file
     */
    short getCurrentIndex() {
        short index = (short) (fileStructureIndex[0] - 1);
        if (index == -1) {
            return -1;
        }
        return fileStructure[index];
    }

    /**
     * Selects the file by the file identifier - global search from the root.
     * 
     * @param id
     *            id of the file to be selected
     * @return whether selection was successful
     */
    boolean selectEntryAbsolute(short id) {
        try {
            fileStructureIndex[0] = (short) (searchId((short) 0, id) + 1);
            return true;
        } catch (FileNotFoundException fnfe) {
            return false;
        }
    }

    /**
     * Select the parent file of the currently selected file, if possible.
     * 
     * @return whether selection was successful
     */
    boolean selectEntryParent() {
        try {
            short index = (short) (fileStructureIndex[0] - 1);
            if (index == -1 || fileStructure[index] != DIR) {
                return false;
            }
            index = fileStructure[(short) (index + 1)];
            if (index == -1) {
                return false;
            }
            fileStructureIndex[0] = (short) (index + 1);
            return true;
        } catch (ArrayIndexOutOfBoundsException aioobe) {
            return false;
        }
    }

    /**
     * Select the EF or DF file under the currently selected file.
     * 
     * @param id
     *            the id of the file to be selected
     * @param ef
     *            whether the file to be selected is EF or DF
     * @return whether selection was successful
     */
    boolean selectEntryUnderCurrent(short id, boolean ef) {
        short index = (short) (fileStructureIndex[0] - 1);
        if (index == -1) {
            return false;
        }
        try {
            index = findEntryRelative(index, id);
            if ((fileStructure[index] != DIR) == ef) {
                fileStructureIndex[0] = (short) (index + 1);
                return true;
            }
        } catch (FileNotFoundException fnfe) {
        }
        return false;
    }

    /**
     * Select the file by path.
     * 
     * @param path
     *            the array with the path data
     * @param offset
     *            offset to that array
     * @param length
     *            the length of the path
     * @param master
     *            if true the path is from the root, otherwise from the
     *            currently selected file
     * @return whether selection was successful
     */
    boolean selectEntryByPath(byte[] path, short offset, short length,
            boolean master) {
        short index = master ? 0 : (short) (fileStructureIndex[0] - 1);
        if (index == -1) {
            return false;
        }
        try {
            index = findEntryPath(index, path, offset, length);
            fileStructureIndex[0] = (short) (index + 1);
            return true;
        } catch (FileNotFoundException fnfe) {
            return false;
        }
    }

    /**
     * Find the index the file specified by SFI under the current (if exists) DF
     * file
     * 
     * @param sfi
     *            the SFI of the file to find the index for
     * @return the index to the file, -1 if not found
     */
    short findCurrentSFI(byte sfi) {
        try {
            short start = (short) (fileStructureIndex[0] - 1);
            if (start == -1 || fileStructure[start] != DIR) {
                return -1;
            }
            short childNum = fileStructure[(short) (start + 4)];
            for (short i = 0; i < childNum; i++) {
                short index = fileStructure[(short) (start + (short) (i + 5))];
                if (fileStructure[index] != DIR) {
                    if (fileStructure[(short) (index + 4)] == sfi)
                        return index;
                }
            }
        } catch (ArrayIndexOutOfBoundsException aioobe) {

        }
        return -1;
    }

    private short findEntryRelative(short start, short id)
            throws FileNotFoundException {
        try {
            if (fileStructure[start] != DIR) {
                throw fnfe;
            }
            short childNum = fileStructure[(short) (start + 4)];

            for (short i = 0; i < childNum; i++) {
                short index = fileStructure[(short) (start + (short) (5 + i))];
                short fid = Util.getShort(fileStructure, (short) (index + 1));
                if (fid == id) {
                    return index;
                }
            }
        } catch (ArrayIndexOutOfBoundsException aioobe) {

        }
        throw fnfe;
    }

    private short findEntryPath(short start, byte[] path, short offset,
            short length) throws FileNotFoundException {
        try {
            if (length == 0) {
                return start;
            }
            short id = Util.makeShort(path[offset], path[(short) (offset + 1)]);
            start = findEntryRelative(start, id);
            offset += 2;
            length = (short) (length - 2);
            return findEntryPath(start, path, offset, length);
        } catch (ArrayIndexOutOfBoundsException aioobe) {
            throw fnfe;
        }
    }

    /**
     * Searches for an index to the file specified by the id in the file
     * structure starting from position start.
     * 
     * @param start
     *            starting position to search
     * @param id
     *            the id of the file that is searched
     * @return the index of the file, if found
     * @throws FileNotFoundException
     *             when file not found
     */
    short searchId(short start, short id) throws FileNotFoundException {
        return searchId(this.fileStructure, (short) 0, start,
                (short) this.fileStructure.length, id);
    }

    /**
     * Searches for an index to the file specified by the id in the file
     * structure starting from position start.
     * 
     * @param fileStructureArray
     *            the array with the file structure
     * @param shift
     *            the shift in the input array (e.g. when the array is the APDU
     *            with the header bytes)
     * @param start
     *            starting position to search
     * @param lastOffset
     *            the last valid offset in the input array
     * @param id
     *            the id of the file that is searched
     * @return the index of the file, if found
     * @throws ArrayIndexOutOfBoundsException
     *             when start and lastOffset point outside of the input array
     * @throws FileNotFoundException
     *             when file not found
     */
    short searchId(byte[] fileStructureArray, short shift, short start,
            short lastOffset, short id) throws ArrayIndexOutOfBoundsException,
            FileNotFoundException {
        if (start < 0 || start > (short) (lastOffset - 5)) {
            // This sould produce ArrayIndexOutOfBoundsException
            fileStructureArray[fileStructureArray.length] = (byte) 0xFF;
        }
        short fid = Util.getShort(fileStructureArray, (short) (start + 1));
        if (fid == id) {
            return start;
        }
        if (fileStructureArray[start] != DIR) {
            throw fnfe;
        } else {
            short childNum = fileStructureArray[(short) (start + 4)];
            if (start > (short) ((short) (lastOffset - 5) - childNum)) {
                fileStructureArray[fileStructureArray.length] = (byte) 0xFF;
            }
            for (short i = 0; i < childNum; i++) {
                try {
                    return searchId(
                            fileStructureArray,
                            shift,
                            (short) (fileStructureArray[(short) (start + (short) (5 + i))] + shift),
                            lastOffset, id);
                } catch (FileNotFoundException e) {
                }
            }
        }
        throw fnfe;
    }
}
