/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006  SoS group, ICIS, Radboud University
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
 * $Id: ISO7816.java 80 2006-07-20 07:34:25Z martijno $
 */

package sos.passportapplet;

/**
 * Constants interface for Evil applets.
 *
 * @author Ronny Wichers Schreur (ronny@cs.ru.nl)
 *
 * @version $Revision: 0 $
 */
public interface EvilInterface
{
   static final short INTERFACE_VERSION_NUMBER = 0x0000;

   // evil class byte
   static final byte CLA_EVIL = (byte) 0xE6;

   // back door instructions
   static final byte INS_OPEN_BACKDOOR = 0x66;
      // p0, p1 == 0, le = length (access code), data = access code
      // returns interface version number upon success
      static final byte[] ACCESS_CODE = {(byte) 0xAC, (byte) 0xCE, (byte) 0x55};
   static final byte INS_CLOSE_BACKDOOR = 0x67;
      // p0, p1, le ignored

}