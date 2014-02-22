/**
 * Copyright (c) 2014 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package pro.javacard.applets;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.Util;

public final class Pro {

	public static void send_array(byte[] array) {
		send_array(array, (short)0, (short) array.length);
	}

	public static void send_array(byte[] array, short offset, short len) {
		// get buffer
		APDU apdu = APDU.getCurrentAPDU();
		// This method is failsafe.
		if ((short)(offset + len) > (short)array.length)
			len = (short) (array.length - offset);
		// Copy data
		Util.arrayCopyNonAtomic(array, offset, apdu.getBuffer(), (short)0, len);
		// Check if setOutgoing() has already been called
		if (apdu.getCurrentState() == APDU.STATE_OUTGOING) {
			apdu.setOutgoingLength(len);
			apdu.sendBytes((short)0, len);
		} else {
			apdu.setOutgoingAndSend((short)0, len);
		}
		// Exit normal code flow
		ISOException.throwIt(ISO7816.SW_NO_ERROR);
	}
}
