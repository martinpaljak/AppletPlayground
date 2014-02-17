package pro.javacard.applets;

/*
 * Copyright (c) 2013 Yubico AB
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class YkneoOath extends Applet {

	public static final byte NAME_TAG = 0x71;
	public static final byte NAME_LIST_TAG = 0x72;
	public static final byte KEY_TAG = 0x73;
	public static final byte CHALLENGE_TAG = 0x74;
	public static final byte RESPONSE_TAG = 0x75;
	public static final byte T_RESPONSE_TAG = 0x76;
	public static final byte NO_RESPONSE_TAG = 0x77;
	public static final byte PROPERTY_TAG = 0x78;
	public static final byte VERSION_TAG = 0x79;
	public static final byte IMF_TAG = 0x7a;

	public static final byte PUT_INS = 0x01;
	public static final byte DELETE_INS = 0x02;
	public static final byte SET_CODE_INS = 0x03;
	public static final byte RESET_INS = 0x04;

	public static final byte LIST_INS = (byte)0xa1;
	public static final byte CALCULATE_INS = (byte)0xa2;
	public static final byte VALIDATE_INS = (byte)0xa3;
	public static final byte CALCULATE_ALL_INS = (byte)0xa4;
	public static final byte SEND_REMAINING_INS = (byte)0xa5;

	private static final short _0 = 0;

	private static final byte CHALLENGE_LENGTH = 8;

	private byte[] tempBuf;
	private byte[] sendBuffer;

	private OathObj authObj;
	private OathObj scratchAuth;
	private byte[] propBuf;

	private static final byte PROP_AUTH_OFFS = 0;
	private static final byte PROP_SENT_DATA_OFFS = 1;
	private static final byte PROP_REMAINING_DATA_LEN = 3;
	private static final byte PROP_BUF_SIZE = PROP_REMAINING_DATA_LEN + 2;

	private static final short BUFSIZE = 2048;
	private static final short TMP_BUFSIZE = 32;

	private RandomData rng;

	private byte[] identity;

	private static final byte[] version = {0x00,0x02,0x02};

	public YkneoOath() {
		tempBuf = JCSystem.makeTransientByteArray((short) TMP_BUFSIZE, JCSystem.CLEAR_ON_DESELECT);
		sendBuffer = JCSystem.makeTransientByteArray(BUFSIZE, JCSystem.CLEAR_ON_DESELECT);
		propBuf = JCSystem.makeTransientByteArray(PROP_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);
		rng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);

		identity = new byte[CHALLENGE_LENGTH];
		rng.generateData(identity, _0, CHALLENGE_LENGTH);

		authObj = new OathObj();
		scratchAuth = new OathObj();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new YkneoOath().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			byte[] buf = apdu.getBuffer();
			short offs = 0;
			buf[offs++] = VERSION_TAG;
			buf[offs++] = (byte)version.length;
			Util.arrayCopyNonAtomic(version, _0, buf, offs, (short) version.length);
			offs += (byte) version.length;
			buf[offs++] = NAME_TAG;
			short nameLen = (short) identity.length;
			buf[offs++] = (byte) nameLen;
			Util.arrayCopyNonAtomic(identity, _0, buf, offs, nameLen);
			offs += nameLen;

			// if the authobj is set add a challenge
			if(authObj.isActive()) {
				buf[offs++] = CHALLENGE_TAG;
				buf[offs++] = CHALLENGE_LENGTH;
				rng.generateData(buf, offs, CHALLENGE_LENGTH);
				authObj.calculate(buf, offs, CHALLENGE_LENGTH, tempBuf, _0);
				offs += CHALLENGE_LENGTH;
			}
			apdu.setOutgoingAndSend(_0, offs);
			return;
		}

		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short sendLen = 0;

		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short p1p2 = Util.makeShort(p1, p2);
		byte ins = buf[ISO7816.OFFSET_INS];

		if(authObj.isActive() && ins != VALIDATE_INS && ins != RESET_INS) {
			if(propBuf[PROP_AUTH_OFFS] != 1) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			}
		}

		switch (ins) {
		case PUT_INS: // put
			if(p1p2 == 0x0000) {
				handlePut(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case DELETE_INS: // delete
			if(p1p2 == 0x0000) {
				handleDelete(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case SET_CODE_INS: // set code
			if(p1p2 == 0x0000) {
				handleChangeCode(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case RESET_INS: // reset
			if(p1p2 == (short)0xdead) {
				handleReset();
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case LIST_INS: // list
			if(p1p2 == 0x0000) {
				sendLen = handleList(sendBuffer);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case CALCULATE_INS: // calculate
			if(p1 == 0x00 && (p2 == 0x00 || p2 == 0x01)) {
				sendLen = handleCalc(buf, p2, sendBuffer);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case VALIDATE_INS: // validate code
			if(p1p2 == 0x0000) {
				sendLen = handleValidate(buf, sendBuffer);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case CALCULATE_ALL_INS: // calculate all codes
			if(p1 == 0x00 && (p2 == 0x00 || p2 == 0x01)) {
				sendLen = handleCalcAll(buf, p2, sendBuffer);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case SEND_REMAINING_INS: // send data remaining in send buffer
			sendLen = Util.getShort(propBuf, PROP_REMAINING_DATA_LEN);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}

		if(sendLen > 0) {
			sendData(apdu, sendLen);
		}
	}

	private void handleReset() {
		authObj.setActive(false);
		OathObj.firstObject = null;
		OathObj.lastObject = null;
		Util.arrayFillNonAtomic(propBuf, _0, PROP_BUF_SIZE, (byte)0);
		JCSystem.requestObjectDeletion();
	}

	private short handleValidate(byte[] input, byte[] output) {
		if(!authObj.isActive()) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short offs = 5;
		if(input[offs++] != RESPONSE_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(input, offs);
		// make sure we're getting as long input as we expect
		if(len != authObj.getDigestLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		offs += getLengthBytes(len);

		if(Util.arrayCompare(input, offs, tempBuf, _0, len) == 0) {
			propBuf[PROP_AUTH_OFFS] = 1;
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		offs += len;
		if(input[offs++] != CHALLENGE_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}

		len = getLength(input, offs);
		// don't accept a challenge shorter than 8 bytes
		if(len < 8) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		offs += getLengthBytes(len);
		short respLen =  authObj.calculate(input, offs, len, tempBuf, _0);
		output[0] = RESPONSE_TAG;
		output[1] = (byte) respLen;
		Util.arrayCopyNonAtomic(tempBuf, _0, output, (short) 2, respLen);
		return (short) (respLen + 2);
	}

	private void handleChangeCode(byte[] buf) {
		short offs = 5;
		if(buf[offs++] != KEY_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);
		if(len == 0) {
			authObj.setActive(false);
		} else {
			byte type = buf[offs++];
			scratchAuth.setKey(buf, offs, type, (short) (len - 1));
			offs += (short)(len - 1);

			if(buf[offs++] != CHALLENGE_TAG) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			len = getLength(buf, offs);
			offs += getLengthBytes(len);
			short respLen = scratchAuth.calculate(buf, offs, len, tempBuf, _0);
			offs += len;
			if(buf[offs++] != RESPONSE_TAG) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			len = getLength(buf, offs);
			offs += getLengthBytes(len);
			if(len != respLen) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			if(Util.arrayCompare(buf, offs, tempBuf, _0, len) == 0) {
				OathObj oldAuth = authObj;
				authObj = scratchAuth;
				scratchAuth = oldAuth;
				oldAuth.setActive(false);
				authObj.setActive(true);
			} else {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
		}
	}

	private short handleCalc(byte[] challenge, byte p2, byte[] output) {
		short offs = 5;
		if(challenge[offs++] != NAME_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(challenge, offs);
		offs += getLengthBytes(len);
		OathObj object = OathObj.findObject(challenge, offs, len);
		if(object == null) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		offs += len;

		if(challenge[offs++] != CHALLENGE_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		len = getLength(challenge, offs);
		offs += getLengthBytes(len);
		short respOffs = 0;
		if(p2 == 0x00) {
			len = object.calculate(challenge, offs, len, tempBuf, _0);
			output[respOffs++] = RESPONSE_TAG;
		} else {
			len = object.calculateTruncated(challenge, offs, len, tempBuf, _0);
			output[respOffs++] = T_RESPONSE_TAG;
		}

		respOffs += setLength(output, respOffs, (short) (len + 1));
		output[respOffs++] = object.getDigits();
		Util.arrayCopy(tempBuf, _0, output, respOffs, len);

		return (short) (len + getLengthBytes(len) + 2);
	}

	private short handleCalcAll(byte[] challenge, byte p2, byte[] output) {
		short offs = 5;
		if(challenge[offs++] != CHALLENGE_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short chalLen = getLength(challenge, offs++);
		Util.arrayCopyNonAtomic(challenge, offs, tempBuf, _0, chalLen);

		offs = 0;
		OathObj obj;
		for(obj = OathObj.firstObject; obj != null; obj = obj.nextObject) {
			if(!obj.isActive()) {
				continue;
			}
			output[offs++] = NAME_TAG;
			output[offs++] = (byte) obj.getNameLength();
			offs += obj.getName(output, offs);
			short len = 0;
			if((obj.getType() & OathObj.OATH_MASK) == OathObj.TOTP_TYPE) {
				if(p2 == 0x00) {
					output[offs++] = RESPONSE_TAG;
					len = obj.calculate(tempBuf, _0, chalLen, output, (short) (offs + 2));
				} else {
					output[offs++] = T_RESPONSE_TAG;
					len = obj.calculateTruncated(tempBuf, _0, chalLen, output, (short) (offs + 2));
				}
			} else {
				output[offs++] = NO_RESPONSE_TAG;
			}
			output[offs++] = (byte) (len + 1);
			output[offs++] = obj.getDigits();
			offs += len;
		}
		return offs;
	}

	private short handleList(byte[] output) {
		short offs = 0;
		OathObj object;
		for(object = OathObj.firstObject; object != null; object = object.nextObject) {
			if(!object.isActive()) {
				continue;
			}
			output[offs++] = NAME_LIST_TAG;
			output[offs++] = (byte) (object.getNameLength() + 1);
			output[offs++] = object.getType();
			offs += object.getName(output, offs);
		}
		return offs;
	}

	private void handleDelete(byte[] buf) {
		short offs = ISO7816.OFFSET_CDATA;
		if(buf[offs++] != NAME_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);
		OathObj object = OathObj.findObject(buf, offs, len);
		if(object != null) {
			object.setActive(false);
		} else {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}

	private short calculateTotalLen() {
		short res = 0;
		OathObj obj;
		for(obj = OathObj.firstObject; obj != null; obj = obj.nextObject) {
			if(!obj.isActive()) {
				continue;
			}
			res += obj.getNameLength() + 9; // data and bytes add up to 9
		}
		return res;
	}

	private void handlePut(byte[] buf) {
		short offs = ISO7816.OFFSET_CDATA;
		if(buf[offs++] != NAME_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);

		if((short)(calculateTotalLen() + len + 9) > BUFSIZE) {
			// the output will be longer than we can support, error out.
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		}

		OathObj object = OathObj.findObject(buf, offs, len);
		if(object == null) {
			object = OathObj.getFreeObject();
			object.setName(buf, offs, len);
		}
		offs += len;

		if(buf[offs++] != KEY_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		len = getLength(buf, offs);
		offs += getLengthBytes(len);

		byte keyType = buf[offs++];
		if((keyType & OathObj.HMAC_MASK) != OathObj.HMAC_SHA1 && (keyType & OathObj.HMAC_MASK) != OathObj.HMAC_SHA256) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if((keyType & OathObj.OATH_MASK) != OathObj.TOTP_TYPE && (keyType & OathObj.OATH_MASK) != OathObj.HOTP_TYPE) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		byte digits = buf[offs++];

		// protect against tearing (we want to do this as late as possible)
		object.setActive(false);
		object.setDigits(digits);

		object.setKey(buf, offs, keyType, (short) (len - 2));
		offs += (short)(len - 2);

		if(offs < buf.length && buf[offs] == PROPERTY_TAG) {
			offs++;
			object.setProp(buf[offs++]);
		} else {
			object.setProp((byte) 0);
		}
		if(offs < buf.length && buf[offs] == IMF_TAG) {
			offs++;
			if(buf[offs++] == OathObj.IMF_LEN) {
				object.setImf(buf, offs);
				offs += OathObj.IMF_LEN;
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
		} else {
			object.clearImf();
		}
		object.setActive(true);
	}

	private short getLength(byte[] buf, short offs) {
		short length = 0;
		if(buf[offs] <= 0x7f) {
			length = buf[offs];
		} else if(buf[offs] == (byte)0x81) {
			length = buf[(short)(offs + 1)];
		} else if(buf[offs] == (byte)0x82) {
			length = Util.getShort(buf, (short) (offs + 1));
		} else {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		return length;
	}

	private short getLengthBytes(short len) {
		if(len < (short)0x0080) {
			return 1;
		} else if(len <= (short)0x00ff) {
			return 2;
		} else {
			return 3;
		}
	}

	private short setLength(byte[] buf, short offs, short len) {
		if(len < (short)0x0080) {
			buf[offs] = (byte) len;
			return 1;
		} else if(len <= (short)0x00ff) {
			buf[offs++] = (byte)0x81;
			buf[offs] = (byte) len;
			return 2;
		} else {
			buf[offs++] = (byte)0x82;
			Util.setShort(buf, offs, len);
			return 3;
		}
	}

	private void sendData(APDU apdu, short len) {
		byte[] buf = apdu.getBuffer();
		short maxLen = APDU.getOutBlockSize();
		short result;
		short remainingData;
		short toSend = maxLen;

		short sentData = Util.getShort(propBuf, PROP_SENT_DATA_OFFS);
		if(len < maxLen) {
			toSend = len;
		}
		Util.arrayCopy(sendBuffer, sentData, buf, _0, toSend);
		if(len > maxLen) {
			remainingData = (short) (len - maxLen);
			sentData += maxLen;
			len = maxLen;
			if(remainingData > maxLen) {
				result = (short) (ISO7816.SW_BYTES_REMAINING_00 | maxLen);
			} else {
				result = (short) (ISO7816.SW_BYTES_REMAINING_00 | remainingData);
			}
		} else {
			sentData = 0;
			remainingData = 0;
			result = ISO7816.SW_NO_ERROR;
		}

		Util.setShort(propBuf, PROP_SENT_DATA_OFFS, sentData);
		Util.setShort(propBuf, PROP_REMAINING_DATA_LEN, remainingData);

		apdu.setOutgoingAndSend(_0, len);
		if(result != ISO7816.SW_NO_ERROR) {
			ISOException.throwIt(result);
		}
	}
	public static class OathObj {
		public static final byte HMAC_MASK = 0x0f;
		public static final byte HMAC_SHA1 = 0x01;
		public static final byte HMAC_SHA256 = 0x02;

		public static final byte OATH_MASK = (byte) 0xf0;
		public static final byte HOTP_TYPE = 0x10;
		public static final byte TOTP_TYPE = 0x20;

		public static final byte PROP_ALWAYS_INCREASING = 1 << 0;

		private static final short _0 = 0;

		private static final byte hmac_buf_size = 64;
		private static final short NAME_LEN = 64;
		public static final byte IMF_LEN = 4;

		public static OathObj firstObject;
		public static OathObj lastObject;
		public OathObj nextObject;

		private byte[] name;
		private short nameLen;
		private byte type;
		private byte digits;
		private short counter = 0;
		private byte[] imf;
		private boolean active = false;

		private byte[] inner;
		private byte[] outer;
		private static MessageDigest sha;
		private static MessageDigest sha256;
		private MessageDigest digest;

		private byte[] lastChal;
		private short lastOffs;
		private byte props;

		private static byte[] scratchBuf;

		public OathObj() {
			inner = new byte[hmac_buf_size];
			outer = new byte[hmac_buf_size];

			if(scratchBuf == null) {
				scratchBuf = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
			}
		}

		public void setKey(byte[] buf, short offs, byte type, short len) {
			if((type & HMAC_MASK) != HMAC_SHA1 && (type & HMAC_MASK) != HMAC_SHA256) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			if((type & OATH_MASK) != HOTP_TYPE && (type & OATH_MASK) != TOTP_TYPE) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			if(len > hmac_buf_size) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			if((type & HMAC_MASK) == HMAC_SHA1) {
				if(sha == null) {
					sha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
				}
				digest = sha;
			} else if((type & HMAC_MASK) == HMAC_SHA256) {
				if(sha256 == null) {
					sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
				}
				digest = sha256;
			}

			this.type = type;
			this.counter = 0;
			Util.arrayFillNonAtomic(inner, _0, hmac_buf_size, (byte) 0x36);
			Util.arrayFillNonAtomic(outer, _0, hmac_buf_size, (byte) 0x5c);
			for (short i = 0; i < len; i++, offs++) {
				inner[i] = (byte) (buf[offs] ^ 0x36);
				outer[i] = (byte) (buf[offs] ^ 0x5c);
			}
		}

		public void setDigits(byte digits) {
			this.digits = digits;
		}

		public byte getDigits() {
			return digits;
		}

		public byte getType() {
			return type;
		}

		public void setName(byte[] buf, short offs, short len) {
			if(name == null) {
				name = new byte[NAME_LEN];
			}
			nameLen = len;
			Util.arrayCopy(buf, offs, name, _0, len);
		}

		public short getName(byte[] buf, short offs) {
			Util.arrayCopy(name, _0, buf, offs, (short) nameLen);
			return (short) nameLen;
		}

		public short getNameLength() {
			return (short) nameLen;
		}

		public void setProp(byte props) {
			this.props = props;
			if((props & PROP_ALWAYS_INCREASING) == PROP_ALWAYS_INCREASING) {
				if(lastChal == null) {
					lastChal = new byte[hmac_buf_size];
				} else {
					Util.arrayFillNonAtomic(lastChal, _0, hmac_buf_size, (byte) 0);
					lastOffs = 0;
				}
			}
		}

		public void addObject() {
			if(firstObject == null) {
				firstObject = lastObject = this;
			} else if(firstObject == lastObject) {
				firstObject.nextObject = lastObject = this;
			} else {
				lastObject.nextObject = lastObject = this;
			}
		}

		public static OathObj getFreeObject() {
			OathObj object;
			for(object = firstObject; object != null; object = object.nextObject) {
				if(!object.isActive()) {
					break;
				}
			}
			if(object == null) {
				object = new OathObj();
				object.addObject();
			}
			return object;
		}

		public static OathObj findObject(byte[] name, short offs, short len) {
			OathObj object;
			for(object = firstObject; object != null; object = object.nextObject) {
				if(!object.isActive() || len != object.nameLen) {
					continue;
				}
				if(Util.arrayCompare(name, offs, object.name, _0, len) == 0) {
					break;
				}
			}
			return object;
		}

		public short calculate(byte[] chal, short chalOffs, short len, byte[] dest,
				short destOffs) {
			byte[] buf = null;

			if((type & OATH_MASK) == TOTP_TYPE) {
				if(len > hmac_buf_size || len == 0) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				if((props & PROP_ALWAYS_INCREASING) == PROP_ALWAYS_INCREASING) {
					short thisOffs = (short) (hmac_buf_size - len);
					short i = lastOffs < thisOffs ? lastOffs : thisOffs;
					for(; i < hmac_buf_size; i++) {
						if(i < thisOffs) {
							if(lastChal[i] == 0) {
								continue;
							} else {
								ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
							}
						} else {
							break;
						}
					}
					short offs = (short) (i - thisOffs + chalOffs);
					byte compRes = Util.arrayCompare(chal, offs, lastChal, i, len);
					if(compRes == -1) {
						ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
					}
					lastOffs = thisOffs;
					Util.arrayCopy(chal, chalOffs, lastChal, thisOffs, len);
				}
				buf = chal;
			} else if((type & OATH_MASK) == HOTP_TYPE) {
				Util.arrayFillNonAtomic(scratchBuf, _0, (short)8, (byte)0);
				if(imf == null || (imf[0] == 0 && imf[1] == 0 && imf[2] == 0 && imf[3] == 0)) {
					Util.setShort(scratchBuf, (short) 6, counter);
				} else {
					Util.arrayCopyNonAtomic(imf, _0, scratchBuf, (short)4, IMF_LEN);
					short carry = 0;
					short ctr1 = (short) ((counter >>> 8) & 0x00ff);
					short ctr2 = (short) (counter & 0x00ff);
					for(byte j = 7; j > 0; j--) {
						short place = (short) (scratchBuf[j] & 0x00ff);
						if(j == 7) {
							place += ctr2;
						} else if(j == 6) {
							place += ctr1;
						}
						place += carry;
						carry = (byte) (place >>> 8);
						scratchBuf[j] = (byte) (place);
					}
				}
				counter++;
				buf = scratchBuf;
				chalOffs = 0;
				len = 8;
			} else {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}

			digest.reset();
			digest.update(inner, _0, hmac_buf_size);
			short digestLen = digest.doFinal(buf, chalOffs, len, dest, destOffs);

			digest.reset();
			digest.update(outer, _0, hmac_buf_size);
			return digest.doFinal(dest, destOffs, digestLen, dest, destOffs);
		}

		public short calculateTruncated(byte[] chal, short chalOffs, short len,
				byte[] dest, short destOffs) {
			short length = calculate(chal, chalOffs, len, scratchBuf, _0);
			short offs = (short) (scratchBuf[(short)(length - 1)] & 0xf);
			dest[destOffs++] = (byte) (scratchBuf[offs++] & 0x7f);
			dest[destOffs++] = scratchBuf[offs++];
			dest[destOffs++] = scratchBuf[offs++];
			dest[destOffs++] = scratchBuf[offs++];
			return 4;
		}

		public short getDigestLength() {
			return digest.getLength();
		}

		public boolean isActive() {
			return active;
		}

		public void setActive(boolean active) {
			this.active = active;
		}

		public void setImf(byte[] buf, short offs) {
			if(imf == null) {
				imf = new byte[IMF_LEN];
			}
			for(byte i = 0; i < IMF_LEN; i++) {
				imf[i] = buf[offs++];
			}
		}

		public void clearImf() {
			if(imf != null) {
				Util.arrayFillNonAtomic(imf, _0, IMF_LEN, (byte)0);
			}
		}
	}

}
