//  MUSCLE SmartCard Development
//      Authors:          Tommaso Cucinotta <cucinotta@sssup.it>
//                        David Corcoran    <corcoran@linuxnet.com>
//                        Ludovic Rousseau  <ludovic.rousseau@free.fr>
//                        Jamie Nicolson    <nicolson@netscape.com>
//      Package:          CardEdgeApplet
//      Description:      CardEdge implementation with JavaCard
//      Protocol Authors: Tommaso Cucinotta <cucinotta@sssup.it>
//                        David Corcoran <corcoran@linuxnet.com>
//      Modified:
//                        Eirik Herskedal <ehersked@cs.purdue.edu>
//
// BEGIN LICENSE BLOCK
// Copyright (c) 1999-2002 David Corcoran <corcoran@linuxnet.com>
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

import javacard.framework.Util;

/**
 * Memory Manager class.
 *
 * <p>An instance of this class is capable of handling allocation and
 * deallocation of chunks in a large Java byte array that is allocated
 * once during the object instantiation.</p>
 *
 * <p>The Memory Manager allocates or frees memory chunks in the
 * preallocated byte array on demand.</p>
 *
 * <p>No defragmentation is done, actually.</p>
 *
 * <p>Consecutive freed memory chunks are recompacted.</p>
 *
 * <p>Every allocation takes 2 more bytes to store the allocated block
 * size, just before the allocated offset.</p>
 *
 * <p>A free memory block starts with a node (NODE_SIZE bytes):</p>
 *
 * <pre>
 *   short size;
 *   short next;
 * </pre>
 *
 * @author Tommaso Cucinotta
 * @author David Corcoran
 * @author Ludovic Rousseau
 * @version 0.9.9
 */
public class MemoryManager
{

	/**
	 * Special offset value used as invalid offset
	 */
	public static final short NULL_OFFSET = -1;
	private static final byte NODE_SIZE = 4;
	private byte ptr[];
	private short free_head;

	/**
	 * Constructor for the MemoryManager class
	 *
	 * @param mem_size Size of the memory are to be allocated
	 */
	public MemoryManager(short mem_size)
	{
		ptr = null;
		free_head = NULL_OFFSET;
		Init(mem_size);
	}

	private void Init(short mem_size)
	{
		if(ptr != null)
		{
			return;
		} else
		{
			ptr = new byte[mem_size];
			Util.setShort(ptr, (short)0, mem_size);
			Util.setShort(ptr, (short)2, (short)NULL_OFFSET);
			free_head = 0;
			return;
		}
	}

	/**
	 * Allocate memory
	 *
	 * Each allocation takes actually a 2 bytes overhead.
	 *
	 * @param size Size of the memory block
	 * @return The offset at which allocated memory starts or
	 * NULL_OFFSET if an error occurred.
	 * @see #alloc(short)
	 * @see #freemem()
	 */
	public short alloc(short size)
	{
		short offset = free_head;
		short prev = NULL_OFFSET;
		size += 2;
		if(size < NODE_SIZE)
			size = NODE_SIZE;
		short next_offset;
		for(; offset != NULL_OFFSET; offset = next_offset)
		{
			short free_size = Util.getShort(ptr, offset);
			next_offset = Util.getShort(ptr, (short)(offset + 2));
			if(free_size >= size)
			{
				short remain = (short)(free_size - size);
				if(remain >= NODE_SIZE)
				{
					Util.setShort(ptr, offset, remain);
				} else
				{
					size = free_size;
					remain = 0;
					if(prev == NULL_OFFSET)
						free_head = next_offset;
					else
						Util.setShort(ptr, (short)(prev + 2), next_offset);
				}
				Util.setShort(ptr, (short)(offset + remain), size);
				return (short)(offset + remain + 2);
			}
			prev = offset;
		}

		return NULL_OFFSET;
	}

	/**
	 * Free a memory block
	 *
	 * <p>Consecutive free blocks are recompacted. Recompaction happens on
	 * free(). 4 cases are considered: don't recompact, recompact with
	 * next only, with previous only and with both of them.</p>
	 *
	 * @param offset The offset at which the memory block starts; it was
	 * returned from a previous call to {@link #alloc(short)}
	 *
	 * @see #alloc(short)
	 * @see #freemem()
	 */
	public void free(short offset)
	{
		offset -= 2;
		short size = Util.getShort(ptr, offset);
		short prev = NULL_OFFSET;
		short base = free_head;
		boolean found = false;
		short node_next = 0;
		for(; base != NULL_OFFSET; base = node_next)
		{
			node_next = Util.getShort(ptr, (short)(base + 2));
			if(offset < base)
			{
				found = true;
				break;
			}
			prev = base;
		}

		if(found && (short)(offset + size) == base)
		{
			size += Util.getShort(ptr, base);
			Util.setShort(ptr, offset, size);
			if(prev != NULL_OFFSET)
				Util.setShort(ptr, (short)(prev + 2), node_next);
			else
				free_head = node_next;
			base = node_next;
		}
		if(prev != NULL_OFFSET)
		{
			short prev_size = Util.getShort(ptr, prev);
			if((short)(prev + prev_size) == offset)
			{
				Util.setShort(ptr, prev, (short)(prev_size + size));
			} else
			{
				Util.setShort(ptr, (short)(offset + 2), base);
				Util.setShort(ptr, (short)(prev + 2), offset);
			}
		} else
		{
			Util.setShort(ptr, (short)(offset + 2), base);
			free_head = offset;
		}
	}

	/**
	 * Get available free memory
	 *
	 * @return The total amount of available free memory, equal to the
	 * sum of all free fragments' sizes.
	 *
	 * @see #free(short)
	 * @see #alloc(short)
	 */
	public short freemem()
	{
		short offset = free_head;
		short total = 0;
		for(; offset != NULL_OFFSET; offset = Util.getShort(ptr, (short)(offset + 2)))
			total = (short)((total + Util.getShort(ptr, offset)) - 2);

		return total;
	}

	/**
	 * Get the size of a memory block
	 *
	 * @param offset The offset at which the memory block starts
	 */
	public short getBlockSize(short offset)
	{
		return (short)(Util.getShort(ptr, (short)(offset - 2)) - 2);
	}

	/**
	 * Retrieve the Java byte array containing all the memory contents.
	 *
	 * <p>To optimize, we don't use external buffers, but we directly
	 * copy from the memory array.</p>
	 *
	 * <p><b>Use this function only if really required.</b></p>
	 *
	 * @return The Java byte array containing all memory contents
	 */
	public byte[] getBuffer()
	{
		return ptr;
	}

	/**
	 * Read a byte value from memory
	 *
	 * @param base The complete memory location (offset) of the byte to
	 * read
	 * @return The byte value
	 */
	public byte getByte(short base)
	{
		return ptr[base];
	}

	/**
	 * Read a byte value from memory
	 *
	 * @param base The base memory location (offset) of the byte to read
	 * @param offset The offset of the byte (is added to the base
	 * parameter)
	 * @return The byte value
	 */
	public byte getByte(short base, short offset)
	{
		return ptr[(short)(base + offset)];
	}

	/**
	 * Copy a byte sequence from memory
	 *
	 * @param dst_bytes[] The destination byte array
	 * @param dst_offset The offset at which the sequence will be copied
	 * in dst_bytes[]
	 * @param src_base The base memory location (offset) of the source
	 * byte sequence
	 * @param src_offset The offset of the source byte sequence (is
	 * added to the src_base parameter)
	 * @param size The number of bytes to be copied
	 */
	public void getBytes(byte dst_bytes[], short dst_offset, short src_base, 
	                     short src_offset, short size)
	{
		Util.arrayCopy(ptr, (short)(src_base + src_offset), 
		               dst_bytes, dst_offset, size);
	}

	/**
	 * Gets the size of the greatest chunk of available memory
	 *
	 * @return The size of the greatest free memory chunk, or zero if
	 * there is no free mem left
	 */
	public short getMaxSize()
	{
		short max_size = 2;
		for(short base = free_head; base != NULL_OFFSET; 
		    base = Util.getShort(ptr, (short)(base + 2)))
		{
			short size = Util.getShort(ptr, base);
			if(size > max_size)
				max_size = size;
		}

		return (short)(max_size - 2);
	}

	/**
	 * Read a short value from memory
	 *
	 * @param base The base memory location (offset) of the short to
	 * read
	 * @return The short value
	 */
	public short getShort(short base)
	{
		return Util.getShort(ptr, base);
	}

	/**
	 * Read a short value from memory
	 *
	 * @param base The base memory location (offset) of the short to
	 * read
	 * @param offset The offset of the short (is added to the base
	 * parameter)
	 * @return The short value
	 */
	public short getShort(short base, short offset)
	{
		return Util.getShort(ptr, (short)(base + offset));
	}

	/**
	 * Resize (only clamping is supported) a previously allocated memory
	 * chunk
	 *
	 * @param offset Memory offset as returned by alloc()
	 * @param new_size ew size of the memory block
	 * @return True if it was possible to realloc(), False otherwise
	 *
	 * @see #alloc(short)
	 * @see #free(short)
	 * @see #freemem()
	 */
	public boolean realloc(short offset, short new_size)
	{
		short actual_size = Util.getShort(ptr, (short)(offset - 2));
		new_size += 2;
		if(new_size < 3 || (short)(actual_size - new_size) < NODE_SIZE)
		{
			return false;
		} else
		{
			Util.setShort(ptr, (short)(offset - 2), new_size);
			Util.setShort(ptr, (short)((offset + new_size) - 2), (short)(actual_size - new_size));
			free((short)(offset + new_size));
			return true;
		}
	}

	/**
	 * Set a byte value into memory
	 *
	 * @param base The complete memory location (offset) of the byte to
	 * set
	 * @param b The new byte value
	 */
	public void setByte(short base, byte b)
	{
		ptr[base] = b;
	}

	/**
	 * Set a byte value into memory
	 *
	 * @param base The base memory location (offset) of the byte to set
	 * @param offset The offset of the byte (is added to the base
	 * parameter)
	 * @param b The new byte value
	 */
	public void setByte(short base, short offset, byte b)
	{
		ptr[(short)(base + offset)] = b;
	}

	/**
	 * Copy a byte sequence into memory
	 *
	 * @param dst_base The base memory location (offset) of the
	 * destination byte sequence
	 * @param dst_offset The offset of the destination byte sequence (is
	 * added to the dst_base parameter)
	 * @param src_bytes[] The source byte array
	 * @param src_offset The offset at which the source sequence starts
	 * in src_bytes[]
	 * @param size The number of bytes to be copied
	 */
	public void setBytes(short dst_base, short dst_offset, byte src_bytes[], short src_offset, short size)
	{
		Util.arrayCopy(src_bytes, src_offset, ptr, (short)(dst_base + dst_offset), size);
	}

	/**
	 * Set a short value into memory
	 *
	 * @param base The complete memory location (offset) of the short to
	 * set
	 * @param b The short value
	 */
	public void setShort(short base, short b)
	{
		Util.setShort(ptr, base, b);
	}

	/**
	 * Set a short value into memory
	 */
	public void setShort(short base, short offset, short b)
	{
		Util.setShort(ptr, (short)(base + offset), b);
	}
}

