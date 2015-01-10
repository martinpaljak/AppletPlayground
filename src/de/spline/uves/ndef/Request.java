package de.spline.uves.ndef;

import javacard.framework.*;

public abstract class Request {

	static final byte classbyte = ISO7816.CLA_ISO7816;
	static byte insbyte;

	public boolean isApplicable(APDU apdu, State state) {
		byte buffer[] = apdu.getBuffer();

		if (buffer[ISO7816.OFFSET_CLA] != classbyte) {
			return false;
		}

		if (buffer[ISO7816.OFFSET_INS] != insbyte) {
			return false;
		}

		return true;
	}

	public abstract State process(APDU apdu, State state);

	// -- usefull helpers ---------------------------

	protected short decodeLcLength(byte[] buffer) {
		return buffer[ISO7816.OFFSET_LC];
		// TODO: decode propperly three bytes values
	}
}
