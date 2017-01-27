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
 * \brief The ISO 7816 compliant GidsFileSystem class.
 *
 * It is the root of the file structure and is therefor equivalent to the ISO Master File (MF).
 * Normally, most of the file system oriented operations should happen through one object of this class.
 *
 * Due to the ISO 7816-4 DF and EF selection (see section 7.1) the currently selected DF and EF
 * are being saved internally. File-related operations are being executed upon those selected files respectively.
 * It is therefor possible to select a file and execute a number of operations upon this file without the need to
 * specify a target in each individual method call. This also saves execution time and reduces stack usage.
 *
 */
public class GidsFileSystem extends ApplicationFile {
    /* Additional ISO Status Words */

    public static final byte OFFSET_CURRENT_DF = 0;
    public static final byte OFFSET_CURRENT_EF = 1;

    private Object[] currentlySelectedFiles = null;
    short currentRecordNum;
    private TransmitManager transmitManager = null;
    public static final short AFDID = 0x3FFF;

    private GidsPINManager pinManager = null;
    /**
     * \brief Instantiate a new ISO 7816 compliant GidsFileSystem.
     *
     * The GidsFileSystem class should normally only be instanciated once. It represents the file system and
     * is therefor equivalemt to the ISO Master File (MF).
     * Most of the file system related operations are performed through the returned object.
     *
     * \see GidsFileSystem.
     *
     * \param fileID The file ID of the master file. Should be 0x3F00 as specified by ISO.
     *
     * \param fileControlInformation The FCI according to ISO 7816-4 table 12. Necessary tags: 82, 83. No copy is made.
     */
    public GidsFileSystem(GidsPINManager pinManager, TransmitManager transmitManager, short fileID, byte[] fileControlParameter, byte[] fileControlInformation, byte[] fileManagementData) {
        super(fileID, fileControlParameter, fileControlInformation, fileManagementData);
        this.currentRecordNum = 0;
        this.currentlySelectedFiles = JCSystem.makeTransientObjectArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        this.currentlySelectedFiles[OFFSET_CURRENT_DF] = this;
        this.pinManager = pinManager;
        this.transmitManager = transmitManager;
        // file system is in creation state
    }


    /**
     * \brief Get the currently selected DF.
     *
     * \return The currently selected DF.
     */
    public DedicatedFile getCurrentlySelectedDF() {
        return ((DedicatedFile)currentlySelectedFiles[OFFSET_CURRENT_DF]);
    }

    /**
     * \brief Set the currently selected DF.
     *
     * \param fileID The ID of the file.
     *
     * \throw NotFoundException If the specified file was not found or was of the wrong type.
     */
    public void setCurrentlySelectedDF(short fileID) throws NotFoundException {
        selectFile( findFile(fileID, SPECIFY_DF) );
        return;
    }

    /**
     * \brief Get the currently selected Elementary File.
     *
     * \return The currently selected EF.
     */
    public ElementaryFile getCurrentlySelectedEF() {
        return ((ElementaryFile)currentlySelectedFiles[OFFSET_CURRENT_EF]);
    }

    /**
     * \brief Set the currently selected Elementary File.
     *
     * \brief fileID The ID of the file.
     *
     * \throw NotFoundException If the specified file was not found or was of the wrong type.
     */
    public void setCurrentlyselectedEF(short fileID) throws NotFoundException {
        selectFile( findFile(fileID, SPECIFY_EF) );
        return;
    }

    /**
     * \brief Search for the DF with the specified name.
     *
     * \param dfName The array containing the up to 16 byte long DedicatedFile name.
     *
     * \param nameOffset The offset at which the DF name begins in the name array.
     *
     * \param nameLength The length of the DF name.
     *
     * \throw NotFoundException If the file was not found.
     *
     * \return The requested DedicatedFile (if found).
     */
    public DedicatedFile findDedicatedFileByName(byte[] dfName, short nameOffset, short nameLength) throws NotFoundException {
        if (isName(dfName, nameOffset, nameLength)) {
            return this;
        }
        return super.findDedicatedFileByNameRec(dfName, nameOffset, nameLength);
    }


    /**
     * \brief find the file with the specified file ID.
     *
     * \param fileID the ID of the file.
     *
     * \param flag A flag to specify if the currently selected EF or DF is the target (SPECIFY_EF, SPECIFY_DF, SPECIFY_ANY).
     *
     * \throw NotFoundException If the file could not be found.
     *
     * \return The File (if found).
     */
    public File findFile(short fileID, byte flag) throws NotFoundException {
        if(fileID == getFileID() && flag != SPECIFY_EF) {
            return this;
        }
        return super.findChildrenRec(fileID, flag);
    }

    public CRTKeyFile findKeyCRT(byte keyID) throws NotFoundException {
        File file = findFile(Util.makeShort((byte)0xB0, keyID), SPECIFY_EF);
        if (!(file instanceof CRTKeyFile)) {
            throw NotFoundException.getInstance();
        }
        return (CRTKeyFile) file;
    }

    /**
     * \brief Set the given file as the selected.
     *
     * If the file is a DedicatedFile, only the currently selected DF is changed.
     * In case of an ElementaryFile the currently selected EF will be the file specified and the
     * currently selected DF will become its parent according to ISO 7816-4, section 7.1.1.
     *
     * \param file The file to select. Must be of DedicatedFile, GidsFileSystem or any subclass of ElementaryFile.
     * 			It should be member of the file system hierarchy (not checked).
     */
    public void selectFile(File file) {
        if(file == null) {
            currentlySelectedFiles[OFFSET_CURRENT_DF] = this;
            currentlySelectedFiles[OFFSET_CURRENT_EF] = null;
        } else if(file instanceof DedicatedFile) {
            currentlySelectedFiles[OFFSET_CURRENT_DF] = file;
            currentlySelectedFiles[OFFSET_CURRENT_EF] = null;
        } else if (file instanceof ElementaryFile) {
            currentlySelectedFiles[OFFSET_CURRENT_EF] = file;
            currentlySelectedFiles[OFFSET_CURRENT_DF] = ((ElementaryFile)currentlySelectedFiles[OFFSET_CURRENT_EF]).getParentDF();
            this.currentRecordNum = 0;
        }
        return;
    }

    /**
     * \brief Add a file to the currently selected DedicatedFile.
     *
     * The currently selected DF becomes the parent of the file.
     * The DF's child and the EF's parent relation is being updated.
     *
     * \param file A reference of the file to save.
     *
     * \throw NotEnoughSpaceException If the maximum amount of
     * 			children would have been exceeded.
     */
    public void addFile(File file) throws NotEnoughSpaceException {
        file.setParentDF(getCurrentlySelectedDF());
        getCurrentlySelectedDF().addChildren(file);
        return;
    }


    /**
     * \brief "Safely" instantiate a File according to the provided File Control Information.
     *
     * Used by processCreateFile().
     *
     * \callergraph
     *
     * \param fci The array containing the file control information (FCI) according to
     *				ISO7816-4 table 12. Mandatory Tags: 82, 83. A copy of the FCI will be
     *				made for the new file.
     *
     * \param offset The offset of the FCI information in the array.
     *
     * \param length The length of the FCI information. Should be consistent with the length
     *					field if the FCI (6F) tag.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED.
     *
     * \return The new file of the FCI was valid, null else.
     */
    public File getSafeFile(byte[] fci, short offset, short length) throws ISOException, InvalidArgumentsException, NotFoundException {
        short fileID;
        byte fileDescByte;
        final short innerLength, innerOffset;
        short pos, len;

        /* **********************
         * Check FCI structure. *
         ************************/
        // Are we in bounds?
        if((short)(fci.length) <= (short)(offset+length)) {
            throw InvalidArgumentsException.getInstance();
        }

        // FCI must begin with tag "6F". Or we have FCP, tag "62".
        if(fci[(offset)] != (byte) 0x6F
                && fci[(offset)] != (byte) 0x62) {
            throw NotFoundException.getInstance();
        }

        // length and length-field of outer FCI tag consistency check.
        innerLength = UtilTLV.decodeLengthField(fci, (short)(offset+1));
        if(innerLength != (short)(length-1-UtilTLV.getLengthFieldLength(fci, (short)(offset+1)))) {
            throw InvalidArgumentsException.getInstance();
        }

        // Let innerOffset point to the first inner TLV entry.
        innerOffset = (short) (offset + 1 + UtilTLV.getLengthFieldLength(fci, (short)(offset+1)));

        // Now we check for the consistency of the lower level TLV entries.
        if( ! UtilTLV.isTLVconsistent(fci, innerOffset, innerLength) ) {
            throw InvalidArgumentsException.getInstance();
        }

        // Extract the FID from the FCI which is passed to the FileXXX contructor and saved
        // separately for performance reasons.
        pos = UtilTLV.findTag(fci, innerOffset, innerLength, (byte) 0x83);
        len = UtilTLV.decodeLengthField(fci, (short)(pos+1));
        if (len != (short) 2) {
            throw InvalidArgumentsException.getInstance();
        }
        fileID = Util.getShort(fci, (short)(pos+1+UtilTLV.getLengthFieldLength(fci, (short)(pos+1))));
        // The fileID must be unique.
        try {
            this.findFile(fileID, SPECIFY_ANY);
            throw InvalidArgumentsException.getInstance();
        } catch(NotFoundException e) {

        }

        // Check and get the File Descriptor Byte (ISO 7816-4 table 14).
        pos = UtilTLV.findTag(fci, innerOffset, innerLength, (byte) 0x82);
        len = UtilTLV.decodeLengthField(fci, (short)(pos+1));
        // Ensure position found and correct length:
        if(len < (short)1 || len > (short)6) {
            throw InvalidArgumentsException.getInstance();
        }
        fileDescByte = fci[(short)(pos+2)];

        byte[] fciEEPROM = null;
        if(fileDescByte  == 0x39) {
            // BER-TLV
            // Check the permissions.
            ((DedicatedFile)currentlySelectedFiles[OFFSET_CURRENT_DF]).CheckPermission(pinManager, ACL_OP_DF_CREATE_EF);
            fciEEPROM = new byte[length];
            Util.arrayCopy(fci, offset, fciEEPROM, (short) 0, length);
            return new BerTlvFile(fileID, fciEEPROM);
        } else if(fileDescByte  == 0x18) {
            // key file descriptor
            // Check if there is a CRT template

            // Search the CRT tag (A5). If not found, then raise an error
            try {
                pos = UtilTLV.findTag(fci, innerOffset, innerLength, (byte) 0xA5);
                len = UtilTLV.decodeLengthField(fci, (short)(pos+1));
            } catch (NotFoundException e) {
                throw InvalidArgumentsException.getInstance();
            }
            CRTKeyFile.CheckCRT(fci, pos, len);
            ((DedicatedFile)currentlySelectedFiles[OFFSET_CURRENT_DF]).CheckPermission(pinManager, ACL_OP_DF_CREATE_EF);
            fciEEPROM = new byte[length];
            Util.arrayCopy(fci, offset, fciEEPROM, (short) 0, length);
            return new CRTKeyFile(fileID, fciEEPROM, (short) (pos - offset), len);
        } else {
            // Not a supported file format.
            throw InvalidArgumentsException.getInstance();
        }
    }



    /* **************************************
     * processXXX methods for ISO commands: *
     ****************************************/

    /* ISO 7816-4 */

    /**
     * \brief Process the SELECT (FILE) apdu.
     *
     * This method updates the currently selected EF or DF, according to the parameters in the apdu.
     * Every selection method according to ISO 7816-4 Table 39 is valid.
     * There are limitations of the P2 byte (b8...b1)  at the moment, however:
     * 	- The first or only occurence is the only supported file occurence (b2b1 = 00)
     *	- No FMD is returned. (b4b3 != 10, if b4b3 = 00 then the response only contains the FCP template.)
     *
     * \param apdu The SELECT (FILE) apdu
     *
     * \throw ISOException SW_INCORRECT_P1P2 and SW_FILE_NOT_FOUND.
     */
    public void processSelectFile(APDU apdu, boolean selectingApplet) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short fid;
        File fileToSelect = null;

        if (selectingApplet) {
            fileToSelect = this;
        } else {

            // Only "first or only occurence" supported at the moment (ISO 7816-4 Table 40).
            if((p2 & 0xF3) != 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            // Bytes received must be Lc.
            lc = apdu.setIncomingAndReceive();

            // Select the file.
            switch(p1) {
            case 0x00: /* MF, DF or EF using FID */
                if(lc == 0) {
                    fileToSelect = this;
                } else if(lc == 2) {
                    // we have a FID
                    fid = Util.makeShort(buf[ISO7816.OFFSET_CDATA], buf[(short)(ISO7816.OFFSET_CDATA+1)]);
                    if (fid == AFDID) {
                        fileToSelect = this;
                    } else {
                        try {
                            fileToSelect = findFile(fid , SPECIFY_ANY);
                        } catch(NotFoundException e) {
                            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                        }
                    }
                }
                break;
            case 0x04: /* by DF name */
                try {
                    fileToSelect = findDedicatedFileByName(buf, ISO7816.OFFSET_CDATA, lc);
                } catch(NotFoundException e) {
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }

        selectFile( fileToSelect );

        /*
         * The file is selected now. We still have to check P2 to see if we need to return any FCI/FCP/FMD information.
         * If we have to, we can use the apdu buffer to save the TLV encoded entries as that is what we want to send back anyway (for performance reasons).
         * We don't use javacardx.framework.tlv.BERTLV as smartcard support is scarce..
         */
        lc = 0; // We re-use lc here for the length of the response data.
        switch(p2 & 0xFC) {
        case 0x00:
            /* Return FCI. */
            if (fileToSelect instanceof ApplicationFile) {
                byte[] fci = ((ApplicationFile) fileToSelect).getFileControlInformation();
                if(fci != null) {
                    Util.arrayCopy(fci, (short) 0, buf, (short) 0, (short) (fci.length));
                    lc += (short) (fci.length);
                } else {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
            } else {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            break;
        case 0x04:
            // Return FCP.
            if(fileToSelect.getFileControlParameter() != null) {
                Util.arrayCopy(fileToSelect.getFileControlParameter(), (short) 0, buf, (short) 0, (short) fileToSelect.getFileControlParameter().length);
                lc += (short) fileToSelect.getFileControlParameter().length;
            }
            break;
        case 0x08:
            // Return FMD.
            if (fileToSelect instanceof ApplicationFile) {
                byte[] fmd = ((ApplicationFile) fileToSelect).getFileManagementData();
                if(fmd != null) {
                    Util.arrayCopy(fmd, (short) 0, buf, (short) 0, (short) fmd.length);
                    lc += (short) fmd.length;
                } else {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
            } else {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            break;
        case 0x0C:
            // Return nothing.
            break;
        }
        if( lc > 0) {
            apdu.setOutgoingAndSend((short) 0, lc);
        }
        return;
    }


    /**
     * \brief Process the DELETE FILE apdu.
     *
     * \attention Only deletion by FID is supported. Lc must be 2, the DATA field
     * 				must contain the file ID. P1P2 must be 0000.
     *
     * \todo Add support for other file identification methods as in SELECT.
     *
     * \param apdu The DELETE FILE apdu.
     *
     * \throw ISOException SW_INCORRECT_P1P2, SW_WRONG_LENGTH, SW_FILE_NOT_FOUND and
     *			SW_SECURITY_STATUS_NOT_SATISFIED.
     */
    public void processDeleteFile(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        File fileToDelete = null;

        // Only P1P2 = 0000 is currently supported.
        // (File identifier must be encoded in the command data field.)
        if( p1 != 0x00 || p2 != 0x00 ) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();

        // One FID in DATA.
        if (lc == 0) {
            fileToDelete = getCurrentlySelectedEF();
            if (fileToDelete == null) {
                fileToDelete = getCurrentlySelectedDF();
            }
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Don't delete the MF.
        if(fileToDelete == this) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        // Permissions.
        fileToDelete.CheckPermission(pinManager, ACL_OP_EF_DELETE);

        // Update current DF before deletion.
        currentlySelectedFiles[OFFSET_CURRENT_DF] = (fileToDelete.getParentDF());
        currentlySelectedFiles[OFFSET_CURRENT_EF] = null;

        // Remove from tree. Garbage collector has already been called by deleteChildren().
        try {
            getCurrentlySelectedDF().deleteChildren(fileToDelete.getFileID());
        } catch(NotFoundException e) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    }

    /**
     * \brief Process the CREATE FILE apdu.
     *
     * This method creates a file, adds it to the filesystem structure and selects it.
     * Configuration options are taken from the DATA field of the APDU. (I.e. P1 and P2 must be 00.)
     * The data field of the APDU must be 2-level nested TLV encoded. The upper level is the FCI (6F) or FCP (62) tag.
     * The nested information will be added to the file as FCI. Also, the following information is being taken in
     * order to allocate the right ressources:
     *		- The file ID (tag 83)
     *		- The file description byte (tag 82) to determine the type, also following information to determine record
     *			sizes and amounts in case of non-transparent EFs.
     *		- In the case of a transparent EF, the data size (excluding structural information) (tag 80) in order to
     * 			allocate enough space.
     *
     * \param apdu The SELECT (FILE) apdu
     *
     * \throw ISOException SW_INCORRECT_P1P2, SW_DATA_INVALID, SW_FILE_FULL and SW_SECURITY_STATUS_NOT_SATISFIED.
     */
    public void processCreateFile(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;

        // Only P1P2 = 0000 supported.
        // (File identifier and parameters must be encoded in the command data field.)
        if( p1 != 0x00 || p2 != 0x00 ) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();

        try {
            // Add the file to the filesystem and select it.
            File fileToAdd = getSafeFile(buf, ISO7816.OFFSET_CDATA, lc); // getSafeFile performs permission checks.
            addFile(fileToAdd);
            selectFile(fileToAdd);
        } catch (NotFoundException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch(NotEnoughSpaceException e) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        } catch(SystemException e) {
            if(e.getReason() == SystemException.NO_RESOURCE) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        return;
    }


    public void processGetData(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte ins = buf[ISO7816.OFFSET_INS];
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc, pos = 0, len = 0, fileID;
        File file = null;
        BerTlvFile bertlvfile = null;

        if (ins != (byte) 0xCB) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();

        if (p1 == 0x3F && p2 == (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } else if (p1 == 0x00 && p2 == 0x00) {
            file = getCurrentlySelectedEF();
        } else if (p1 == (byte) 0xFF && p2 == (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        } else {
            fileID = Util.getShort(buf, (short) 2);
            try {
                file = findFile(fileID, SPECIFY_EF);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        }

        if(!(file instanceof BerTlvFile)) {
            ISOException.throwIt(ErrorCode.SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE);
        }
        bertlvfile = (BerTlvFile) file;

        file.CheckPermission(pinManager, ACL_OP_DO_GET_DATA);

        fileID = bertlvfile.getFileID();

        if (fileID != (short) 0x2F00 && fileID != (short) 0x2F01 && fileID != (short) 0x3F00  && fileID != (short) 0x0000) {
            // implicit selection not valid for every file
            selectFile(bertlvfile);
        }
        try {
            // Extract the FID from the FCI which is passed to the FileXXX contructor and saved
            // separately for performance reasons.
            pos = UtilTLV.findTag(buf, ISO7816.OFFSET_CDATA, (byte) lc, (byte) 0x5C);
            if (buf[(short)(pos+(short)1)] == (byte) 0) {
                len = (short) 0;
            } else {
                len = UtilTLV.decodeLengthField(buf, (short)(pos+1));
            }
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if ((len == 0)
                || (len == 1 && buf[(short) (pos+2)]== (byte)0x5C)) {
            transmitManager.sendRecords(apdu, bertlvfile.getAllData());
        } else {
            try {
                Record record = bertlvfile.getData(buf, (short)(pos+1+UtilTLV.getLengthFieldLength(buf, (short)(pos+1))), (short) (ISO7816.OFFSET_CDATA + lc));
                transmitManager.sendRecord(apdu,record);
            } catch (NotFoundException e) {
                ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            }
        }
    }


    public void processPutData(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte ins = buf[ISO7816.OFFSET_INS];
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short fileID;
        File file = null;
        BerTlvFile bertlvfile = null;
        short size;
        Record record = null;
        if (ins != (byte) 0xDB) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        if (p1 == (byte) 0x3F && p2 == (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } else if (p1 == 0x00 && p2 == 0x00) {
            file = getCurrentlySelectedEF();
        } else if (p1 == (byte) 0xFF && p2 == (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        } else {
            fileID = Util.getShort(buf, (short) 2);
            try {
                file = findFile(fileID, SPECIFY_EF);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        }

        if(!(file instanceof BerTlvFile)) {
            ISOException.throwIt(ErrorCode.SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE);
        }
        bertlvfile = (BerTlvFile) file;

        file.CheckPermission(pinManager, ACL_OP_DO_PUT_DATA);

        selectFile(bertlvfile);
        lc = apdu.setIncomingAndReceive();

        record = transmitManager.returnCachedRecord();
        if (record == null && TransmitManager.isCommandChainingCLA(apdu)) {
            // handle first chained APDU
            size = UtilTLV.CheckBERTLV(buf, ISO7816.OFFSET_CDATA, (short) (ISO7816.OFFSET_CDATA + lc));
            try {
                record = bertlvfile.addChildren(buf, ISO7816.OFFSET_CDATA, size, lc);
            } catch(NotEnoughSpaceException e) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            } catch(SystemException e) {
                if(e.getReason() == SystemException.NO_RESOURCE) {
                    ISOException.throwIt(ISO7816.SW_FILE_FULL);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            transmitManager.setCachedRecord(record);
            transmitManager.setCachedOffset(lc);
        } else if (record != null) {
            // handle next chained APDU
            short offset = transmitManager.returnCachedOffset();
            byte[] data = record.GetData();
            if ((short) (offset + lc) > data.length) {
                transmitManager.clearCachedRecord();
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, data, offset, lc);
            transmitManager.setCachedOffset((short) (offset + lc));
            if ((short) (offset + lc) == data.length) {
                transmitManager.clearCachedRecord();
            } else if (!TransmitManager.isCommandChainingCLA(apdu)) {
                // the data sent is too short
                // clear it
                transmitManager.clearCachedRecord();
                Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0);
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            // else wait for the next record
        } else {
            size = UtilTLV.CheckBERTLV(buf, ISO7816.OFFSET_CDATA, (short) (ISO7816.OFFSET_CDATA + lc));
            if (size <= 0) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            try {
                bertlvfile.addChildren(buf, ISO7816.OFFSET_CDATA, size, lc);
            } catch(NotEnoughSpaceException e) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            } catch(SystemException e) {
                if(e.getReason() == SystemException.NO_RESOURCE) {
                    ISOException.throwIt(ISO7816.SW_FILE_FULL);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
        }
        return;
    }

    public void processActivateFile(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        if (p1 != 0x00 || p2 != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        // only a file or the applet can be selected
        File file = getCurrentlySelectedEF();
        if (file == null) {
            file = getCurrentlySelectedDF();
            if (file != this) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        }

        file.CheckPermission(pinManager, ACL_OP_EF_ACTIVATE);

        file.setState(STATE_OPERATIONAL_ACTIVATED);

        if (file == this) {
            pinManager.SetInitializationMode(false);
        }

    }

}
