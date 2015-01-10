package de.spline.uves.ndef;

import javacard.framework.*;

/** Implementation of NDEF (Nfc Data Exchange Format) as JavaCard applet. This Applets allows to send
 *  static data (set at compile time) to an NDEF enabled reader (eg. Android Smartphones). An example
 *  application is the transmissions of links over NFC.
 *
 *  @author Yves Müller
 *  @version 0.0.1
 *
 *  This code is released in 2014 under the WTFPL (Version 2)
 */

public class Ndef extends Applet {

	// constants for instructions
	static final byte INS_READ_BINARY = (byte) 0xB0;

	// mutable state of applet
	private State state;

	protected Request handlers[] = {new SelectRequest()};

	protected Ndef() {
		register();
	}

	/**
	 * Installs this applet.
	 *
	 * @param bArray the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new Ndef();
	}

	// TODO: add javadoc
	/*        protected short processReadBinary(byte[] buffer) {

	 if (state == EF_SELECTED && ef == CAPABILITY_CONTAINER_EF) {
	 short offset = (short)(buffer[ISO7816.OFFSET_P1] << 8 + buffer[ISO7816.OFFSET_P2]);
	 byte offset_byte3;
	 short le = 0;

	 if (0x0000 <= offset && offset <= 0x7FFF) { // short offset
	 le = buffer[ISO7816.OFFSET_CDATA]; // Todo: proper le decoding
	 return sendCapabilityContainer(buffer, offset, le);

	 } else if ( offset == 0x0000 && // long offsets
	 buffer[ISO7816.OFFSET_CDATA] == 5 &&
	 buffer[ISO7816.OFFSET_CDATA + 1] == 0x54 &&
	 buffer[ISO7816.OFFSET_CDATA + 2] == 0x03){


	 offset = (short)(
	 buffer[ISO7816.OFFSET_CDATA + 1] << 8 |
	 buffer[ISO7816.OFFSET_CDATA + 2]);

	 offset_byte3 = buffer[ISO7816.OFFSET_CDATA + 3];

	 le = buffer[ISO7816.OFFSET_CDATA + 5]; // Todo: proper le decoding

	 // feature not supported yet
	 ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
	 } else { // invalid encoded offset
	 ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	 }
	 } else {
	 ISOException.throwIt(ISO7816.SW_FILE_INVALID);
	 }
	 return 0;
	 }*/

	/**
	 * Process incoming APDU messages from the reader.
	 *
	 * @see APDU
	 * @param apdu the incoming APDU
	 * @exception ISOException with the response bytes per ISO 7816-4
	 */
	public void process(APDU apdu) {

		short recivedNow = apdu.setIncomingAndReceive();
		byte buffer[] = apdu.getBuffer();
		short responseLength = 0;

		Request handler = null;

		for (byte i = 0; i < handlers.length; i++) {
			if (handlers[i].isApplicable(apdu, state)) {
				handler = handlers[i];
			}
		}

		if (handler == null) {
			state.application = State.IDLE;
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

		} else {
			state = handler.process(apdu, state);
		}
	}
	// validate class
	/*                if (buffer[ISO7816.OFFSET_CLA] != ISO7816.CLA_ISO7816) {
	 ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	 }

	 if (handler[0].isApplicable(apdu)) {
	 processSelect(buffer);
	 apdu.setOutgoing();
	 apdu.setOutgoingLength(responseLength);
	 } else {

	 // dispatch by instruction
	 switch (buffer[ISO7816.OFFSET_INS]) {

	 case ISO7816.INS_SELECT:
	 processSelect(buffer);

	 apdu.setOutgoing();
	 apdu.setOutgoingLength(responseLength);
	 break;

	 case INS_READ_BINARY:
	 responseLength = processReadBinary(buffer);
	
	 apdu.setOutgoing();
	 apdu.setOutgoingLength(responseLength);
	 break;

	 case (byte)0x90:
	 apdu.setOutgoing();
	 apdu.setOutgoingLength((short)3);
	 buffer[0] = state;
	 buffer[1] = (byte)(ef >> 8);
	 buffer[2] = (byte)(ef);
	 apdu.sendBytes((short)0, (short)3);
	 break;

	 default: // unkown instruction
	 state = IDLE;
	 ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	 }
	 }

	 }*/
}
