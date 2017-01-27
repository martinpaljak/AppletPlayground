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

/**
 * \brief Definition of some error codes
 * Note: use an interface instead of a class to save space on the card
 */
public interface ErrorCode {
    public static final short SW_PIN_TRIES_REMAINING = 0x63C0; // See ISO 7816-4 section 7.5.1
    public static final short SW_REFERENCE_DATA_NOT_FOUND = 0x6A88;
    public static final short SW_COMMAND_NOT_ALLOWED_GENERAL = 0x6900;
    public static final short SW_TERMINATION_STATE = 0x6285;
    public static final short SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE = 0x6981;
    public static final short SW_COMMAND_CHAINING_NOT_SUPPORTED = 0x6884;
}
