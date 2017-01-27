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
 * \brief The InvalidArgumentsException class.
 *
 * \attention This singleton is not thread-safe.
 */
public class InvalidArgumentsException extends Exception {
    /**
     *
     */
    public static InvalidArgumentsException instance;

    /**
     * \brief Private access constructor (Singleton pattern).
     */
    private InvalidArgumentsException() {

    }

    /**
     * \brief Get the instance.
     *
     * \return The InvalidArgumentsException instance.
     */
    public static InvalidArgumentsException getInstance() {
        if(instance == null) {
            instance = new InvalidArgumentsException();
        }
        return instance;
    }

}
