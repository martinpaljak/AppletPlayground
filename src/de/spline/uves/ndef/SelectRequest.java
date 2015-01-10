package de.spline.uves.ndef;

import javacard.framework.*;

public class SelectRequest extends Request {
	static byte insbyte = ISO7816.INS_SELECT;

	public State process(APDU apdu, State state) {
		state.application = State.SELECTED;
		return state;
	}
}
