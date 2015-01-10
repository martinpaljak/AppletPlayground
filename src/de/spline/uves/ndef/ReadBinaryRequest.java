package de.spline.uves.ndef;

import javacard.framework.*;

public class ReadBinaryRequest extends Request {

	static byte insbyte = Ndef.INS_READ_BINARY;

	// constant container
	static final byte[] capabilityContainer = {(byte) 0x00, (byte) 0x0F, // size of cc
			(byte) 0x20, // mapping version 2.0
			(byte) 0xFF, (byte) 0xFF, // maximum le (TODO: get from manual)
			(byte) 0x00, (byte) 0xFF, // maximum lc (TODO: get from manual)
			(byte) 0x04, (byte) 0x06, // extended ndef file (TLV header)
			(byte) 0x00, (byte) 0x01, // file identifier
			(byte) 0xFF, (byte) 0xFF, // maximum file length
			(byte) 0x00, // read access condition [any]
			(byte) 0xFF // write access condition [none]
	};

	public boolean isApplicable(APDU apdu, State state) {
		byte buffer[] = apdu.getBuffer();
		if (super.isApplicable(apdu, state)) {
			if (state.application == State.EF_SELECTED) {
				return true;
			}
		}

		return false;
	}

	public State process(APDU apdu, State state) {
		byte buffer[] = apdu.getBuffer();
		if (state.ef == ContainerSelectRequest.CAPABILITY_CONTAINER_EF) {
			short offset = (short) (buffer[ISO7816.OFFSET_P1] << 8 + buffer[ISO7816.OFFSET_P2]);
			byte offset_byte3;
			short le = 0;

			if (0x0000 <= offset && offset <= 0x7FFF) { // short offset
				le = buffer[ISO7816.OFFSET_CDATA]; // Todo: proper le decoding

				apdu.setOutgoing();
				apdu.setOutgoingLength(le);
				sendCapabilityContainer(buffer, offset, le);
				apdu.sendBytes((short) 0, le);

			} else if (offset == 0x0000
					&& // long offsets
					buffer[ISO7816.OFFSET_CDATA] == 5
					&& buffer[ISO7816.OFFSET_CDATA + 1] == 0x54
					&& buffer[ISO7816.OFFSET_CDATA + 2] == 0x03) {

				offset = (short) (buffer[ISO7816.OFFSET_CDATA + 1] << 8 | buffer[ISO7816.OFFSET_CDATA + 2]);

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

		return state;
	}

	protected short sendCapabilityContainer(byte[] buffer, short offset,
			short length) {
		return Util.arrayCopyNonAtomic(capabilityContainer, offset, buffer,
				(short) 0, length);
	}
}
