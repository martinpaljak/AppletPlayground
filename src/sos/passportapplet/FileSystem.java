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
 * $Id: FileSystem.java 915 2009-03-24 15:25:42Z woj76 $
 */

package sos.passportapplet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * FileSystem.
 * 
 * @author Martijn Oostdijk (martijno@cs.ru.nl)
 * @author Cees-Bart Breunesse (ceesb@cs.ru.nl)
 * 
 * @version $Revision: 915 $
 */
public class FileSystem {
    static final short EF_DG1_FID = (short) 0x0101;

    static final short EF_DG2_FID = (short) 0x0102;

    static final short EF_DG3_FID = (short) 0x0103;

    static final short EF_DG4_FID = (short) 0x0104;

    static final short EF_DG5_FID = (short) 0x0105;

    static final short EF_DG6_FID = (short) 0x0106;

    static final short EF_DG7_FID = (short) 0x0107;

    static final short EF_DG8_FID = (short) 0x0108;

    static final short EF_DG9_FID = (short) 0x0109;

    static final short EF_DG10_FID = (short) 0x010A;

    static final short EF_DG11_FID = (short) 0x010B;

    static final short EF_DG12_FID = (short) 0x010C;

    static final short EF_DG13_FID = (short) 0x010D;

    static final short EF_DG14_FID = (short) 0x010E;

    static final short EF_DG15_FID = (short) 0x010F;

    static final short EF_SOD_FID = (short) 0x011D;

    static final short EF_COM_FID = (short) 0x011E;

    static final short EF_CVCA_FID = (short) 0x011C;

    static final short SOS_LOG_FID = (short) 0xdead;

    private static final short EF_DG1_INDEX = (short) 0;

    private static final short EF_DG2_INDEX = (short) 1;

    private static final short EF_DG3_INDEX = (short) 2;

    private static final short EF_DG4_INDEX = (short) 3;

    private static final short EF_DG5_INDEX = (short) 4;

    private static final short EF_DG6_INDEX = (short) 5;

    private static final short EF_DG7_INDEX = (short) 6;

    private static final short EF_DG8_INDEX = (short) 7;

    private static final short EF_DG9_INDEX = (short) 8;

    private static final short EF_DG10_INDEX = (short) 9;

    private static final short EF_DG11_INDEX = (short) 10;

    private static final short EF_DG12_INDEX = (short) 11;

    private static final short EF_DG13_INDEX = (short) 12;

    private static final short EF_DG14_INDEX = (short) 13;

    private static final short EF_DG15_INDEX = (short) 14;

    private static final short EF_SOD_INDEX = (short) 15;

    private static final short EF_COM_INDEX = (short) 16;

    private static final short EF_CVCA_INDEX = (short) 17;

    private static final short SOS_LOG_INDEX = (short) 18;

    private Object[] files;

    private short[] fileSizes;

    public FileSystem() {
        short size = (short) (SOS_LOG_INDEX + 1);
        files = new Object[size];
        fileSizes = new short[size];
    }

    public void createFile(short fid, short size) {
        createFile(fid, size, null);
    }

    public void createFile(short fid, short size, CVCertificate certObject) {
        short idx = getFileIndex(fid);

        // first create determines maximum file size
        if (files[idx] == null)
            files[idx] = new byte[size];

        if (certObject != null) {
            certObject.cvcaFileReference = (byte[]) files[idx];
        }

        if (((byte[]) files[idx]).length < size)
            ISOException.throwIt(ISO7816.SW_FILE_FULL);

        fileSizes[idx] = size;
    }

    public void writeData(short fid, short file_offset, byte[] data,
            short data_offset, short length) {
        byte[] file = getFile(fid);
        short fileSize = getFileSize(fid);

        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        if (fileSize < (short) (file_offset + length))
            ISOException.throwIt(ISO7816.SW_FILE_FULL);

        Util.arrayCopy(data, data_offset, getFile(fid), file_offset, length);
    }

    public byte[] getFile(short fid) {
        short idx = getFileIndex(fid);
        if (idx == -1) {
            return null;
        }
        return (byte[]) files[idx];
    }

    public short getFileSize(short fid) {
        short idx = getFileIndex(fid);
        if (idx == -1) {
            return -1;
        }
        return fileSizes[idx];
    }

    private static short getFileIndex(short fid) throws ISOException {
        if ((fid == EF_DG3_FID && !PassportApplet.certificate.isDG3Accessible())
                || (fid == EF_DG4_FID && !PassportApplet.certificate
                        .isDG4Accessible())) {
            ISOException
                    .throwIt(PassportApplet.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        switch (fid) {
        case EF_DG1_FID:
            return EF_DG1_INDEX;
        case EF_DG2_FID:
            return EF_DG2_INDEX;
        case EF_DG3_FID:
            return EF_DG3_INDEX;
        case EF_DG4_FID:
            return EF_DG4_INDEX;
        case EF_DG5_FID:
            return EF_DG5_INDEX;
        case EF_DG6_FID:
            return EF_DG6_INDEX;
        case EF_DG7_FID:
            return EF_DG7_INDEX;
        case EF_DG8_FID:
            return EF_DG8_INDEX;
        case EF_DG9_FID:
            return EF_DG9_INDEX;
        case EF_DG10_FID:
            return EF_DG10_INDEX;
        case EF_DG11_FID:
            return EF_DG11_INDEX;
        case EF_DG12_FID:
            return EF_DG12_INDEX;
        case EF_DG13_FID:
            return EF_DG13_INDEX;
        case EF_DG14_FID:
            return EF_DG14_INDEX;
        case EF_DG15_FID:
            return EF_DG15_INDEX;
        case EF_SOD_FID:
            return EF_SOD_INDEX;
        case EF_COM_FID:
            return EF_COM_INDEX;
        case EF_CVCA_FID:
            return EF_CVCA_INDEX;
        case SOS_LOG_FID:
            return SOS_LOG_INDEX;
        default:
            return -1;
        }
    }
}
