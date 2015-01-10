package de.spline.uves.ndef;

import javacard.framework.*;

public class ContainerSelectRequest extends SelectRequest {

	// constants for elementary files
	static final short CAPABILITY_CONTAINER_EF = (short) 0xE103;

	public boolean isApplicable(APDU apdu, State state) {
		byte buffer[] = apdu.getBuffer();
		if (super.isApplicable(apdu, state)) {

			if (buffer[ISO7816.OFFSET_P1] == (byte) 0x00 && /* select by file identfier */
			buffer[ISO7816.OFFSET_P2] == (byte) 0x0C && /* first and only occourence */
			decodeLcLength(buffer) == (short) 0x02 /* Lc = 2 */) {
				return true;
			}
		}
		return false;
	}

	public State process(APDU apdu, State state) {
		byte buffer[] = apdu.getBuffer();
		state.ef = (short) ((buffer[ISO7816.OFFSET_CDATA] << 8) + buffer[ISO7816.OFFSET_CDATA + 1]);

		// filter for vlalid file identifiers
		switch (state.ef) {
			case CAPABILITY_CONTAINER_EF :
				state.application = State.EF_SELECTED;
				break;
			default :
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
				break;
		}

		return state;
	}
}
