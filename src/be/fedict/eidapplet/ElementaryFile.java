/*
 * Quick-Key Toolset Project.
 * Copyright (C) 2010 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */
package be.fedict.eidapplet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class ElementaryFile extends File {
	// link to parent DF
	private DedicatedFile parentFile;
	// data stored in file
	private byte[] data;
	// current size of data stored in file
	short size;
	public ElementaryFile(short fid, DedicatedFile parent, byte[] d) {
		super(fid);
		parentFile = parent;
		parent.addSibling(this);
		data = d;
		size = (short) d.length;
	}
	public ElementaryFile(short fid, DedicatedFile parent, short maxSize) {
		super(fid);
		parentFile = parent;
		parent.addSibling(this);
		data = new byte[maxSize];
		size = (short) 0;
	}
	public DedicatedFile getParent() {
		return parentFile;
	}
	public byte[] getData() {
		if (active == true)
			return data;
		else {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return null;
		}
	}
	public short getCurrentSize() {
		if (active == true)
			return size;
		else {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return 0;
		}
	}
	public short getMaxSize() {
		return (short) data.length;
	}
	public short[] getPath() {
		short[] path = parentFile.getPath();
		path[(short) (path.length + 1)] = getFileID();
		return path;
	}
	public void eraseData(short offset) {
		Util.arrayFillNonAtomic(data, offset, size, (byte) 0);
	}
	public void updateData(short dataOffset, byte[] newData, short newDataOffset, short length) {
		// update size
		size = (short) (dataOffset + length);
		// copy new data
		Util.arrayCopy(newData, newDataOffset, data, dataOffset, length);
	}
}
