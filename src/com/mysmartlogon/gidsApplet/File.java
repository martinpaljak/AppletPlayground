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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * \brief The File class acting as superclass for any file.
 */
public abstract class File {
    private final short fileID;
    private DedicatedFile parentDF;

    final byte[] fcp;
    private final short aclPos;
    private byte state;
    /* Access Control Operations */
    public static final byte ACL_OP_01 = (byte) 0x01;
    public static final byte ACL_OP_02 = (byte) 0x02;
    public static final byte ACL_OP_04 = (byte) 0x04;
    public static final byte ACL_OP_08 = (byte) 0x08;
    public static final byte ACL_OP_10 = (byte) 0x10;
    public static final byte ACL_OP_20 = (byte) 0x20;
    public static final byte ACL_OP_40 = (byte) 0x40;

    public static final byte ACL_OP_DF_DELETE_CHILD = (byte) 0x01;
    public static final byte ACL_OP_DF_CREATE_EF = (byte) 0x02;
    public static final byte ACL_OP_DF_CREATE_DF = (byte) 0x04;
    public static final byte ACL_OP_DF_DEACTIVATE = (byte) 0x08;
    public static final byte ACL_OP_DF_ACTIVATE = (byte) 0x10;
    public static final byte ACL_OP_DF_TERMINATE = (byte) 0x20;
    public static final byte ACL_OP_DF_DELETE_SELF = (byte) 0x40;

    public static final byte ACL_OP_EF_READ = (byte) 0x01;
    public static final byte ACL_OP_EF_UPDATE = (byte) 0x02;
    public static final byte ACL_OP_EF_WRITE = (byte) 0x04;
    public static final byte ACL_OP_EF_DEACTIVATE = (byte) 0x08;
    public static final byte ACL_OP_EF_ACTIVATE = (byte) 0x10;
    public static final byte ACL_OP_EF_TERMINATE = (byte) 0x20;
    public static final byte ACL_OP_EF_DELETE = (byte) 0x40;

    public static final byte ACL_OP_DO_GET_DATA = (byte) 0x01;
    public static final byte ACL_OP_DO_PUT_DATA = (byte) 0x02;

    public static final byte ACL_OP_KEY_GETPUBLICKEY = (byte) 0x01;
    public static final byte ACL_OP_KEY_PUTKEY = (byte) 0x02;
    public static final byte ACL_OP_KEY_MANAGE_SEC_ENV = (byte) 0x04;
    public static final byte ACL_OP_KEY_GENERATE_ASYMETRIC = (byte) 0x08;


    /* Card/Applet lifecycle states */
    // see 7.4.10 Life cycle status table 14
    public static final byte STATE_CREATION = (byte) 0x01; // No restrictions, PUK not set yet.
    public static final byte STATE_INITIALISATION = (byte) 0x03; // PUK set, PIN not set yet. PUK may not be changed.
    public static final byte STATE_OPERATIONAL_ACTIVATED = (byte) 0x07; // PIN is set, data is secured.
    public static final byte STATE_OPERATIONAL_DEACTIVATED = (byte) 0x06; // Applet usage is deactivated. (Unused at the moment.)
    public static final byte STATE_TERMINATED = (byte) 0x0F; // Applet usage is terminated. (Unused at the moment.)


    /**
     * \brief Abstract constructor to be called by subclasses.
     *
     * \param fileID The ID of the file.
     *
     * \param fileControlInformation The FCI according to ISO 7816-4 table 12. Necessary tags: 82, 83. No copy is made.
     */
    public File(short fileID, byte[] fileControlParameter) {
        this.fileID = fileID;
        this.parentDF = null;
        this.fcp = fileControlParameter;
        // Save the position of the ACL (Value field) in the FCI for performance reasons.
        // If the position is -1, then every action may be performed.

        // try the following tag by order
        // tag 0x86 = security attribute in proprietary format
        // tag 0x8C = compact format

        short pos;
        try {
            pos = UtilTLV.findTag(fcp, (short) 2, fcp[(short)1], (byte) 0x8C);

        } catch (NotFoundException e) {
            pos = -1;
        } catch (InvalidArgumentsException e) {
            pos = -1;
        }
        this.aclPos = pos;

        state = STATE_CREATION;
    }

    public void CheckPermission(GidsPINManager pinManager, byte flag_operation) {
        if (state == STATE_CREATION) {
            if (this instanceof ApplicationFile) {
                // every operation is allowed on the application on the creation state
                return;
            }
            if (this instanceof ElementaryFile) {
                // only a transition to operational state is allowed
                if (flag_operation != ACL_OP_EF_ACTIVATE) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
            }
            if (this instanceof DedicatedFile) {
                // only a transition to operational state is allowed
                if (flag_operation != ACL_OP_DF_ACTIVATE) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
            }
        } else if (state == STATE_TERMINATED) {
            if (this instanceof ApplicationFile) {
                // every operation is denied on the application on the termination state
                ISOException.throwIt(ErrorCode.SW_TERMINATION_STATE);
            }
            if (this instanceof ElementaryFile) {
                // only a transition to operational state is allowed
                if (flag_operation != ACL_OP_EF_DELETE) {
                    ISOException.throwIt(ErrorCode.SW_TERMINATION_STATE);
                }
            }
            if (this instanceof DedicatedFile) {
                // only a transition to operational state is allowed
                if (flag_operation != ACL_OP_DF_DELETE_SELF) {
                    ISOException.throwIt(ErrorCode.SW_TERMINATION_STATE);
                }
            }
        }
        CheckACLRequirements(pinManager, flag_operation);
    }


    /**
     * \brief Get the relevant ACL byte for the operation.
     *
     * \param flag_operation The operation. One of ACL_OP_*.
     *
     * \return The ACL byte.
     */
    private void CheckACLRequirements(GidsPINManager pinManager, byte flag_operation) {
        if(aclPos == -1) {
            return; // Any operation is allowed if there is no ACL.
        }
        byte accessmod = fcp[(short)(aclPos+2)];
        short index = (short)(aclPos+2);
        if ((accessmod & ACL_OP_40) != 0) {
            index++;
            if (flag_operation == ACL_OP_40) {
                pinManager.CheckACL(fcp[index]);
            }
        }
        if ((accessmod & ACL_OP_20) != 0) {
            index++;
            if (flag_operation == ACL_OP_20) {
                pinManager.CheckACL(fcp[index]);
            }
        }
        if ((accessmod & ACL_OP_10) != 0) {
            index++;
            if (flag_operation == ACL_OP_10) {
                pinManager.CheckACL(fcp[index]);
            }
        }
        if ((accessmod & ACL_OP_08) != 0) {
            index++;
            if (flag_operation == ACL_OP_08) {
                pinManager.CheckACL(fcp[index]);
            }
        }
        if ((accessmod & ACL_OP_04) != 0) {
            index++;
            if (flag_operation == ACL_OP_04) {
                pinManager.CheckACL(fcp[index]);
            }
        }
        if ((accessmod & ACL_OP_02) != 0) {
            index++;
            if (flag_operation == ACL_OP_02) {
                pinManager.CheckACL(fcp[index]);
            }
        }
        if ((accessmod & ACL_OP_01) != 0) {
            index++;
            if (flag_operation == ACL_OP_01) {
                pinManager.CheckACL(fcp[index]);
            }
        }
        // TODO: check if a second ACL is following
        // typically ACL for contact & contactless operations
        return; // Any operation is allowed if there is no ACL.
    }



    /**
     * \brief Get the file identifier.
     *
     * \return The file ID.
     */
    public short getFileID() {
        return this.fileID;
    }

    /**
     * \brief Get the parent Dedicated File (DF).
     *
     * \return The parent DF or null if the file had not been added yet.
     */
    public DedicatedFile getParentDF() {
        return this.parentDF;
    }

    /**
     * \brief Set the parent Dedicated File (DF).
     *
     * \param parent the parent DF.
     */
    public void setParentDF(DedicatedFile parent) {
        this.parentDF = parent;
    }

    /**
     * \brief Get the File Control Information (FCI).
     *
     * \return The FCI array.
     */
    public final byte[] getFileControlParameter() {
        return this.fcp;
    }

    public final byte getState() {
        return state;
    }

    public final void setState(byte state) {
        this.state = state;
    }

    /**
     * \brief Clear the contents of the file.
     *
     * Used when deleting files and JCSystem.requestObjectDeletion() is not
     * implemented.
     */
    abstract void clearContents();
}
