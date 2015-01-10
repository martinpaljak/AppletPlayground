//  SmartCard Applet
//      Authors:          Robert Relyea     <rrelyea@redhat.com>
//      Package:          CardEdgeApplet
//      Description:      CardEdge implementation with JavaCard
//
// BEGIN LICENSE BLOCK
// Copyright (C) 2006 Red Hat, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// Changes to this license can be made only by the copyright author with
// explicit written consent.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Alternatively, the contents of this file may be used under the terms of
// the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
// case the provisions of the LGPL are applicable instead of those above. If
// you wish to allow use of your version of this file only under the terms
// of the LGPL, and not to allow others to use your version of this file
// under the terms of the BSD license, indicate your decision by deleting
// the provisions above and replace them with the notice and other
// provisions required by the LGPL. If you do not delete the provisions
// above, a recipient may use your version of this file under the terms of
// either the BSD license or the LGPL.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
// END LICENSE_BLOCK

package com.redhat.ckey.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * ASN1 parser Class
 *
 * <p>This Simplistic ASN.1 parser does not interpret tags, it simply finds
 * elements based on where their fields are supposed to wind up at. </p>
 *
 *
 * Object fields:
 * <pre>
 *    short[] newSize; // way to get around java's restrictions on pass by ref. 
 *    byte[] data
 * </pre>
 *
 * @author Robert Relyea
 * @version 0.0.1
 *
 */
public class ASN1
{
    public static final short SW_BAD_DER_DATA = (short)0x9cd0;
    private final short NEXT = 0;
    private final short SIZE = 1;
    private final short END  = 2;
    private short[] params;

    public ASN1() 
    {
	params=JCSystem.makeTransientShortArray((short)3,
						JCSystem.CLEAR_ON_DESELECT);
    }
  
    public short GetEnd()
    {
	return params[END];
    } 

    public short GetSize()
    {
	return params[SIZE];
    } 

    public short GetNext()
    {
	return params[NEXT];
    } 

    public byte GetTag(byte buf[], short offset, short end)
    {
	if (end <= offset) {
	    ISOException.throwIt(SW_BAD_DER_DATA);
	}
	return buf[offset];
    }
	
    public short Unwrap(byte buf[], short offset, short end, short dbg)
    {
	byte tag;
	byte len;
	short length = 0;

	if (end < (short)(offset+2)) {
	    ISOException.throwIt(SW_BAD_DER_DATA);
	}
	tag = buf[offset++];
	if (tag == 0) {
	    ISOException.throwIt(SW_BAD_DER_DATA);
	}
	len = buf[offset++];
	length = Util.makeShort((byte)0,len);

	if ((len & 0x80) != 0) {
	    short count = Util.makeShort((byte)0,(byte)(len & 0x7f));
	    if (end < (short)(offset+count)) {
	        ISOException.throwIt(SW_BAD_DER_DATA);
	    }
	    if (count > 2) {
	        ISOException.throwIt(SW_BAD_DER_DATA);
	    }
            length = 0;
	    while (count-- > 0) {
		length = (short)((length << 8) 
				| Util.makeShort((byte)0,buf[offset++]));
	    }
	}
	params[SIZE] = length;
	params[NEXT] = ((short)(offset+length));
	params[END] = ((short)(offset+length));
	return offset;
    }

    public short Skip(byte buf[], short offset, short end, short dbg)
    {
	Unwrap(buf,offset,end,dbg);
	return params[NEXT];
    }

    public short UnwrapBitString(byte buf[], short offset, short end, short dbg)
    {
	if (buf[offset] != 0) {
	    ISOException.throwIt(SW_BAD_DER_DATA);
	}
	if (end < (short)(offset+1)) {
	    ISOException.throwIt(SW_BAD_DER_DATA);
	}
	params[SIZE]--;
	return (short)(offset+1);
    }

    public short Signed2Unsigned(byte buf[], short offset, short end, short dbg)
    {
	short startOffset = offset;
	short startSize=params[SIZE];
	for (; offset < end && buf[offset] == 0 ; offset++){
	    params[SIZE]--;
	}
	if (offset >= end) {
	    ISOException.throwIt(SW_BAD_DER_DATA);
	}
	return offset;
    }
}


