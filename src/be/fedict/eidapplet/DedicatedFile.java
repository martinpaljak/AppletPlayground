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

public class DedicatedFile extends File {
	// link to parent DF
	private DedicatedFile parentFile;
	// list of sibling files (either EF or DF)
	private static final byte MAX_SIBLINGS = 10;
	private File[] siblings = new File[MAX_SIBLINGS];
	// number of siblings
	private byte number = 0;
	// constructor only used by MasterFile
	protected DedicatedFile(short fid) {
		super(fid);
		// MasterFile does not have a parent, as it is the root of all files
		parentFile = null;
	}
	public DedicatedFile(short fid, DedicatedFile parent) {
		super(fid);
		parentFile = parent;
		parent.addSibling(this);
	}
	public short[] getPath() {
		short[] path;
		if (parentFile != null) {
			path = parentFile.getPath();
			path[(short) (path.length + 1)] = getFileID();
		} else
			path = new short[] { getFileID() };
		return path;
	}
	public DedicatedFile getParent() {
		return parentFile;
	}
	public byte getNumberOfSiblings() {
		return number;
	}
	public File getSibling(short fid) {
		for (byte i = 0; i < number; i++) {
			if (siblings[i].getFileID() == fid)
				return siblings[i];
		}
		return null;
	}
	protected void addSibling(File s) {
		if (number < MAX_SIBLINGS)
			siblings[number++] = s;
	}
}
