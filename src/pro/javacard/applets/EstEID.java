package pro.javacard.applets;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

// Placeholder
public class EstEID extends Applet {

	OwnerPIN pin1;
	OwnerPIN pin2;

	private EstEID(byte[] parameters, short offset, byte length) {
		register(parameters, offset, length);
	}

	public static void install(byte[] parameters, short offset, byte length) {
		new EstEID(parameters, offset, length);
	}

	public void process(APDU arg0) throws ISOException {

	}

}
