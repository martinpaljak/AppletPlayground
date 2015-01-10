/* 
 * Copyright (C) 2011  Digital Security group, Radboud University
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
 */
 
package openemv;

import javacard.framework.ISO7816;

/* EMVConstants defines a constants used in the EMV standard and 
 * constants specific to this implementation. It extends ISO7816
 * as some ISO7816 constants are also used by EMV.
 *
 * @author joeri (joeri@cs.ru.nl)
 * @author erikpoll (erikpoll@cs.ru.nl)
  *
 */

public interface EMVConstants extends ISO7816 {

    // commands
    byte INS_GENERATE_AC = (byte) 0xAE;
    byte INS_GET_DATA = (byte) 0xCA;
    byte INS_GET_PROCESSING_OPTIONS = (byte) 0xA8;
    byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
    byte INS_VERIFY = (byte) 0x20;
    byte INS_GET_CHALLENGE = (byte) 0x84 ;
    byte INS_READ_RECORD = (byte) 0xB2;

    // Already defined in ISO7816.java:
    //  INS_SELECT = A4
    //  INS_EXTERNAL_AUTHENTICATE = 82

    // post-issuance commands
    byte INS_APPLICATION_BLOCK = (byte)0x1E;
    byte INS_APPLICATION_UNBLOCK = (byte)0x18;
    byte INS_CARD_BLOCK = (byte)0x16;
    byte INS_PIN_CHANGE_UNBLOCK = (byte)0x24;

    // status words
    short SW_ISSUER_AUTHENTICATION_FAILED = (short)0x6300;

    // constants to record the (persistent) lifecycle state
    byte PERSONALISATION = (byte)0x00;
    byte READY = (byte)0x01;
    byte BLOCKED = (byte)0x02;

    /* codes for cryptogram types used in P1*/
    byte ARQC_CODE = (byte)0x80;
    byte   TC_CODE = (byte)0x40;
    byte  AAC_CODE = (byte)0x00;
    byte  RFU_CODE = (byte)0xC0;
    
    /* types of AC  */
    byte NONE = (byte)0x00;
    byte ARQC = (byte)0x01;
    byte   TC = (byte)0x02;
    byte  AAC = (byte)0x03;

    // types of CVM performed; NONE for none.
    public final static byte PLAINTEXT_PIN = (byte)0x01;
    public final static byte ENCRYPTED_PIN = (byte)0x02;

}
