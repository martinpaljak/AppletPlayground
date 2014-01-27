package pro.javacard.applets;


public interface ISO7816 extends javacard.framework.ISO7816 {
	/** INS code for VERIFY command */
	public final static byte INS_VERIFY = (byte) 0x20;
	/** INS code for CHANGE REFERENCE DATA command */
	public final static byte INS_CHANGE_REFERENCE_DATA = (byte) 0x24;
	/** INS code for RESET RETRY COUNTER command */
	public final static byte INS_RESET_RETRY_COUNTER = (byte) 0x2C;
	/** INS code for SELECT command */
	public final static byte INS_SELECT = (byte) 0xA4;
	/** INS code for READ BINARY command */
	public final static byte INS_READ_BINARY = (byte) 0xB0;
	/** INS code for READ RECORD command */
	public final static byte INS_READ_RECORD = (byte) 0xB2;
	/** INS code for MANAGE SECURITY ENVIRONMENT command */
	public final static byte INS_MANAGE_SECURITY_ENVIRONMENT = (byte) 0x22;
	/** INS code for INTERNAL AUTHENTICATE command */
	public final static byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
	/** INS code for MUTUAL AUTHENTICATE command */
	public final static byte INS_MUTUAL_AUTHENTICATE = (byte) 0x82;
	/** INS code for GET CHALLENGE command */
	public final static byte INS_GET_CHALLENGE = (byte) 0x84;
	/** INS code for UPDATE BINARY command */
	public final static byte INS_UPDATE_BINARY = (byte) 0xD6;
	/** INS code for UPDATE RECORD command */
	public final static byte INS_UPDATE_RECORD = (byte) 0xDC;
	/** INS code for APPEND RECORD command */
	public final static byte INS_APPEND_RECORD = (byte) 0xE2;
	/** INS code for GET DATA command */
	public final static byte INS_GET_DATA = (byte) 0xCA;
	/** INS code for PUT DATA command */
	public final static byte INS_PUT_DATA = (byte) 0xDA;
	/** INS code for CREATE FILE command */
	public final static byte INS_CREATE_FILE = (byte) 0xE0;
	/** INS code for DELETE FILE command */
	public final static byte INS_DELETE_FILE = (byte) 0xE4;
	/** INS code for GENERATE ASYMMETRIC KEY PAIR command */
	public final static byte INS_GENERATE_ASYMMETRIC_KEY_PAIR = (byte) 0x46;
	/** INS code for PERFORM SECURITY OPERATION command */
	public final static byte INS_PERFORM_SECURITY_OPERATION = (byte) 0x2A;
}
