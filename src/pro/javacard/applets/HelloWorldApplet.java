package pro.javacard.applets;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;

// Placeholder
public class HelloWorldApplet extends Applet {

	private HelloWorldApplet(byte[] parameters, short offset, byte length) {
		register(parameters, offset, length);
	}

	public static void install(byte[] parameters, short offset, byte length) {
		new HelloWorldApplet(parameters, offset, length);
	}

	public void process(APDU arg0) throws ISOException {

	}

}
