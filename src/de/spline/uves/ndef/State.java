package de.spline.uves.ndef;

import javacard.framework.*;

public class State {

	// constant for state codings
	static final byte IDLE = 0;
	static final byte SELECTED = 1;
	static final byte EF_SELECTED = 2;

	protected byte application = IDLE;
	protected short ef = (short) 0;
}
