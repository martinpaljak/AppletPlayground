package sos.passportapplet;

/* buffer for ATR Historical Bytes (ATS) must be a global */

public class ATRGlobal {
	public static byte[] ATR_HIST= {(byte) 0x4a,(byte) 0x4d,(byte) 0x52, (byte) 0x54, (byte) 0x44}; // "JMRTD"
	public static byte ATR_HIST_LEN= 0x05;
}
