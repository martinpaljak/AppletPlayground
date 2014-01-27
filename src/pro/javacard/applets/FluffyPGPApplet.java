/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package pro.javacard.applets;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * Implements the GPG Card v 2.0.1 specification without using secure channels or Global Platform
 * for portability.
 * Spec: http://g10code.com/docs/openpgp-card-2.0.pdf
 * Support:
 * - 2048 bit RSA keys
 * - RSA Key import (CRT format)
 * - Random number generation
 * - Private DOs
 *
 * Limitations:
 * - No extended APDU support.
 * - Supports only 2048 bit CRT RSA keys (1024 is too short and most cards don't support 4096 bits)
 * - No secure messaging support.
 * - No support for the cardholder certificate (DO 7F21).
 * - Readability was favored over code size.
 * - Will not run on cards with an APDU buffer smaller than 256 + 5 bytes.
 */
public final class FluffyPGPApplet extends Applet {

  public static final byte CMD_VERIFY = 0x20;
  public static final byte CMD_CHANGE_REFERENCE_DATA = 0x24;
  public static final byte CMD_COMPUTE_PSO = 0x2A;
  public static final byte CMD_RESET_RETRY_COUNTER = 0x2C;
  public static final byte CMD_GENERATE_ASYMETRIC = (byte) 0x47;
  public static final byte CMD_GET_CHALLENGE = (byte) 0x84;
  public static final byte CMD_INTERNAL_AUTHENTICATE = (byte) 0x88;
  public static final byte CMD_GET_RESPONSE = (byte) 0xC0;
  public static final byte CMD_GET_DATA = (byte) 0xCA;
  public static final byte CMD_PUT_DATA = (byte) 0xDA;
  public static final byte CMD_PUT_KEY = (byte) 0xDB;
  public static final byte CMD_TERMINATE_DF = (byte) 0xE6;
  public static final byte CMD_ACTIVATE_FILE = (byte) 0x44;

  private static final short SW_PIN_FAILED_00 = 0x63C0;
  private static final short SW_PIN_BLOCKED = 0x6983;

  public static final byte MAX_TRIES_PIN1 = 3;
  public static final byte MAX_TRIES_RC = 3;
  public static final byte MAX_TRIES_PIN3 = 3;
  public static final byte MAX_PIN_LENGTH = 32;
  private static final byte MIN_PIN1_LENGTH = 6;
  private static final byte MIN_PIN3_LENGTH = 8;

  private static final byte PIN_INDEX_PW1 = 0;
  private static final byte PIN_INDEX_PW3 = 1;
  private static final byte PIN_INDEX_RC = 2;

  private static final short RSA_KEY_LENGTH_BYTES = 256;  // 2048 bits.
  private static final short RSA_KEY_HALF_LENGTH_BYTES = 128;  // For P, Q...
  // The key part order in PUT_KEY
  private static final byte KEY_PART_E = 0;
  private static final byte KEY_PART_PRIME_P = 1;
  private static final byte KEY_PART_PRIME_Q = 2;
  private static final byte KEY_PART_PARAM_PQ = 3;
  private static final byte KEY_PART_PARAM_DP1 = 4;
  private static final byte KEY_PART_PARAM_DQ1 = 5;
  private static final byte KEY_PART_N = 6;

  // Used for command chaining.
  // Byte 0 = last INS, other bytes depend on the command.
  private static final byte TEMP_INS = 0;
  // For the put key command.
  private static final byte TEMP_PUT_KEY_ACCUMULATOR_LENGTH = 1;
  private static final byte TEMP_PUT_KEY_KEY_TYPE = 3;
  private static final byte TEMP_PUT_KEY_KEY_CHUNK = 4;
  private static final byte TEMP_PUT_KEY_EXPECTED_CHUNK_SIZE = 5;
  private static final byte TEMP_PUT_KEY_ACCUMULATOR = 7;
  // For Get Response.
  private static final byte TEMP_GET_RESPONSE_OFFSET = 1;
  private static final byte TEMP_GET_RESPONSE_LENGTH = 3;
  private static final byte TEMP_GET_RESPONSE_DATA = 5;

  // C0: Selection by full or partial DF name.
  // 40: Data coding byte, not used by GPG.
  // 80: Command chaining
  // 00: No life cycle management.
  private final static byte[] historicalBytes = {
      0, 0x73, (byte) 0xC0, 0x40, (byte) 0x80, 0, (byte) 0x90, 0};

  private final static byte[] extendedCapabilities = {
      (byte) 0x78,  // Get Challenge, Key Import, PW1 status changeable, Private DO
      1,  // AES
      0, (byte) 0xFE, // Max challenge length.
      0, 0,  // Maximum length of cardholder certificate = 0.
      0, (byte) 0xFF,  // Maximum length of command data.
      1, (byte) 0,  // Maximum length of response data.
  };

  private final static byte[] algorithmAttributes = {
      1, // RSA
      8, 0, // 2048 bits key
      0, 0x20, // 32 bit exponent.
      3};  // CRT format with n.

  // The spec 4.3.3.7 mandates that the DO are in order and only the ones needed are
  // passed so we effectively always have the same header for a given key size.
  // Values for e.length = 0
  private static final byte[] expectedRSAKeyImportFormat = {
      0x4D, (byte) 0x82, 3, (byte) 0x9F,
      0, 0,  // Key type, masked out before comparing.
      0x7f, 0x48, 0x15,
      (byte) 0x91, 0,  // e
      (byte) 0x92, (byte) 0x81, (byte) RSA_KEY_HALF_LENGTH_BYTES,  // p
      (byte) 0x93, (byte) 0x81, (byte) RSA_KEY_HALF_LENGTH_BYTES,  // q
      (byte) 0x94, (byte) 0x81, (byte) RSA_KEY_HALF_LENGTH_BYTES,  // pq
      (byte) 0x95, (byte) 0x81, (byte) RSA_KEY_HALF_LENGTH_BYTES,  // dp1
      (byte) 0x96, (byte) 0x81, (byte) RSA_KEY_HALF_LENGTH_BYTES,  // dq1
      (byte) 0x97, (byte) 0x82, (byte) 0x01, (byte) 0x0,  // Modulus.
      0x5F, 0x48, (byte) 0x82, 0x03, (byte) 0x80
  };
  // Default PINs according to spec section 4.2
  private final byte[] defaultPIN = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

  private final OwnerPIN[] pins;
  // To distinguish between PW1/PW2, must be AND'ed with the OwnerPIN status.
  private final boolean[] pinSubmitted;
  private final byte[] pinLength;  // Current PIN length to allow Change Reference Data to work.
  private final byte[] privateDO1;
  private final byte[] privateDO2;
  private final byte[] privateDO3;
  private final byte[] privateDO4;
  private final byte[] loginData;
  private final byte[] url;
  private final byte[] name;
  private final byte[] language;
  private final byte[] sex;
  private final byte[] fingerprints;
  private final byte[] caFingerprints;
  private final byte[] generationDates;
  private final byte[] signatureCounter;
  private byte pinValidForMultipleSignatures;
  private final byte[] commandChainingBuffer;
  private final KeyPair signatureKey;
  private final KeyPair confidentialityKey;
  private final KeyPair authenticationKey;
  private final Cipher cipherRSA;
  private final RandomData randomData;
  private boolean terminated = false;

  /**
   * Only this class's install method should create the applet object.
   */
  protected FluffyPGPApplet(byte[] parameters, short offset, byte length) {
    pinLength = new byte[3];
    pins = new OwnerPIN[3];
    pins[PIN_INDEX_PW1] = new OwnerPIN(MAX_TRIES_PIN1, MAX_PIN_LENGTH);
    pins[PIN_INDEX_PW1].update(defaultPIN, (short) 0, MIN_PIN1_LENGTH);
    pinLength[PIN_INDEX_PW1] = MIN_PIN1_LENGTH;
    pins[PIN_INDEX_PW3] = new OwnerPIN(MAX_TRIES_PIN3, MAX_PIN_LENGTH);
    pins[PIN_INDEX_PW3].update(defaultPIN, (short) 0, MIN_PIN3_LENGTH);
    pinLength[PIN_INDEX_PW3] = MIN_PIN3_LENGTH;
    // The resetting code is disabled by default.
    pins[PIN_INDEX_RC] = new OwnerPIN(MAX_TRIES_RC, MAX_PIN_LENGTH);
    pinLength[PIN_INDEX_RC] = 0;
    pinSubmitted = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);

    commandChainingBuffer =
        JCSystem.makeTransientByteArray((short) (TEMP_PUT_KEY_ACCUMULATOR + RSA_KEY_LENGTH_BYTES),
                                        JCSystem.CLEAR_ON_DESELECT);

    privateDO1 = new byte[255];
    privateDO2 = new byte[255];
    privateDO3 = new byte[255];
    privateDO4 = new byte[255];

    loginData = new byte[(short) 255];
    url = new byte[(short) 255];
    name = new byte[(short) 40];
    language = new byte[(short) 9];
    sex = new byte[(short) 1];
    fingerprints = new byte[(short) 60];
    caFingerprints = new byte[(short) 60];
    generationDates = new byte[(short) 12];
    signatureCounter = new byte[(short) 3];
    pinValidForMultipleSignatures = (byte) 0;

    signatureKey = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 2048);
    confidentialityKey = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 2048);
    authenticationKey = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 2048);
    cipherRSA = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
    randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

    register();
  }

  /**
   * Installs this applet.
   *
   * @param parameters  the array containing installation parameters
   * @param offset the starting offset in bArray
   * @param length the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] parameters, short offset, byte length) {
    new FluffyPGPApplet(parameters, offset, length);
  }

  /**
   * Processes an incoming APDU.
   *
   * @param apdu the incoming APDU
   * @throws ISOException with the response bytes per ISO 7816-4
   * @see APDU
   */
  public void process(APDU apdu) {
    byte buffer[] = apdu.getBuffer();
    byte ins = buffer[ISO7816.OFFSET_INS];

    if (ins == CMD_GET_RESPONSE) {
      if (commandChainingBuffer[TEMP_INS] == CMD_GENERATE_ASYMETRIC) {
        short lengthLeftToSend = Util.getShort(commandChainingBuffer, TEMP_GET_RESPONSE_LENGTH);
        if (lengthLeftToSend == 0) {
          return;
        }
        short responseLength = apdu.setOutgoing();
        if (responseLength > lengthLeftToSend) {
          responseLength = lengthLeftToSend;
        }
        lengthLeftToSend -= responseLength;
        short offset = Util.getShort(commandChainingBuffer, TEMP_GET_RESPONSE_OFFSET);
        apdu.setOutgoingLength(responseLength);
        apdu.sendBytesLong(commandChainingBuffer, offset, responseLength);
        if (lengthLeftToSend > (short) 0) {
          Util.setShort(commandChainingBuffer, TEMP_GET_RESPONSE_OFFSET,
                        (short) (offset + responseLength));
          Util.setShort(commandChainingBuffer, TEMP_GET_RESPONSE_LENGTH, lengthLeftToSend);
          ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
        } else {
          Util.setShort(commandChainingBuffer, TEMP_GET_RESPONSE_OFFSET, (short) 0);
        }
      }
      return;
    }

    if (commandChainingBuffer[TEMP_INS] != ins) {
      // Reset the last chained instruction if we get a different command in the middle.
      if (commandChainingBuffer[TEMP_INS] != (byte) 0) {
        Util.arrayFillNonAtomic(commandChainingBuffer, (short) 0,
                                (short) commandChainingBuffer.length, (byte) 0);
      }
    }

    if (selectingApplet()) {
      short aidLength = JCSystem.getAID().getBytes(buffer, (short) 4);
      buffer[0] = 0x6F;
      buffer[1] = (byte) (2 + aidLength);
      buffer[2] = (byte) 0x84;
      buffer[3] = (byte) (aidLength);
      apdu.setOutgoingAndSend((short) 0, (short) (4 + aidLength));
      if (terminated) {
        ISOException.throwIt((short)0x6285);
      }
      return;
    }
    if (terminated && ins != CMD_ACTIVATE_FILE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    short p1p2 = Util.getShort(buffer, ISO7816.OFFSET_P1);
    switch (ins) {
      case CMD_VERIFY:
        verify(apdu);
        break;

      case CMD_CHANGE_REFERENCE_DATA:
        changeReferenceData(apdu);
        break;

      case CMD_RESET_RETRY_COUNTER:
        resetRetryCounter(apdu);
        break;

      case CMD_GET_DATA:
        getData(apdu);
        break;

      case CMD_COMPUTE_PSO:
        if (p1p2 == (short) 0x9E9A) {
          computeSignature(apdu);
        } else if (p1p2 == (short) 0x8086) {
          decrypt(apdu);
        } else {
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        break;

      case CMD_GENERATE_ASYMETRIC:
        if (p1p2 != (short) 0x8000 && p1p2 != (short) 0x8100) {
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        generateAsymetricKey(apdu);
        break;

      case CMD_PUT_DATA:
        putData(apdu);
        break;

      case CMD_GET_CHALLENGE:
        getChallenge(apdu);
        break;

      case CMD_PUT_KEY:
        if (p1p2 != (short) 0x3FFF) {
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        putKey(apdu);
        break;

      case CMD_INTERNAL_AUTHENTICATE:
        if (p1p2 != (short) 0) {
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        internalAuthenticate(apdu);
        break;

      case CMD_TERMINATE_DF:
        terminateDF(apdu);
        break;

      case CMD_ACTIVATE_FILE:
        activateFile(apdu);
        break;

      default:
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }
    commandChainingBuffer[0] = ins;
  }

  /**
   * VERIFY APDU implementation.
   */
  private void verify(APDU apdu) {
    byte buffer[] = apdu.getBuffer();
    if (buffer[ISO7816.OFFSET_P1] != (byte) 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // type = 0x81 or 0x82 -> PIN1, min length = 6
    // type = 0x83 -> PIN2, min length = 8
    byte pinOffset = PIN_INDEX_PW1;
    byte type = buffer[ISO7816.OFFSET_P2];
    byte minLength = MIN_PIN1_LENGTH;
    if (type == (byte) 0x83) {
      pinOffset = PIN_INDEX_PW3;
      minLength = MIN_PIN3_LENGTH;
    } else if (type != (byte) 0x81 && type != (byte) 0x82) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
    if (apdu.setIncomingAndReceive() != length ||
        length > MAX_PIN_LENGTH ||
        length < minLength) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (pins[pinOffset].getTriesRemaining() == 0) {
      ISOException.throwIt(SW_PIN_BLOCKED);
    }
    boolean result = pins[pinOffset].check(buffer, ISO7816.OFFSET_CDATA, (byte) length);
    if (type != (byte) 0x83) {
      pinSubmitted[(byte) (type - 0x81)] = result;
    }
    if (result) {
      ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
    ISOException.throwIt((short) (SW_PIN_FAILED_00 + pins[pinOffset].getTriesRemaining()));
  }

  /**
   * Udpate the PIN and its length in a transaction.
   * @param pinId which PIN will be updated.
   * @param data contains the new PIN.
   * @param dataOffset first byte of the new PIN in the data array.
   * @param newLength the new PIN length.
   */
  private void updatePIN(short pinId, byte[] data, short dataOffset, byte newLength) {
    JCSystem.beginTransaction();
    pins[pinId].update(data, dataOffset, newLength);
    pinLength[pinId] = newLength;
    JCSystem.commitTransaction();
  }

  /**
   * CHANGE REFERENCE DATA APDU implementation.
   */
  private void changeReferenceData(APDU apdu) {
    byte buffer[] = apdu.getBuffer();
    if (buffer[ISO7816.OFFSET_P1] != (byte) 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    byte pinOffset = PIN_INDEX_PW1;
    byte minLength = MIN_PIN1_LENGTH;
    byte type = buffer[ISO7816.OFFSET_P2];
    if (type == (byte) 0x83) {
      pinOffset = PIN_INDEX_PW3;
      minLength = MIN_PIN3_LENGTH;
    } else if (type != (byte) 0x81) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    byte currentLength = pinLength[pinOffset];
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
    if (apdu.setIncomingAndReceive() != length ||
        length > (byte)(currentLength + MAX_PIN_LENGTH) ||
        length < (byte)(currentLength + minLength)) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (pins[pinOffset].getTriesRemaining() == 0) {
      ISOException.throwIt(SW_PIN_BLOCKED);
    }
    if (!pins[pinOffset].check(buffer, ISO7816.OFFSET_CDATA, currentLength)) {
      pinSubmitted[0] = false;
      ISOException.throwIt((short) (SW_PIN_FAILED_00 + pins[pinOffset].getTriesRemaining()));
    }
    updatePIN(pinOffset, buffer, (short) (ISO7816.OFFSET_CDATA + currentLength),
              (byte) (length - currentLength));
  }

  /**
   * RESET RETRY COUNTER ADPU implementation.
   */
  private void resetRetryCounter(APDU apdu) {
    byte buffer[] = apdu.getBuffer();
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
    if (apdu.setIncomingAndReceive() != length) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    if (buffer[ISO7816.OFFSET_P2] != (byte) 0x81) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    if (buffer[ISO7816.OFFSET_P1] == (byte) 0) {
      // We need to check RC then update P1 (if RC is set).
      byte rcLength = pinLength[PIN_INDEX_RC];
      if (pins[PIN_INDEX_RC].getTriesRemaining() == 0 || rcLength == 0) {
        ISOException.throwIt(SW_PIN_BLOCKED);
      }
      if (length < (byte)(rcLength + MIN_PIN1_LENGTH) ||
    		  length > (byte)(rcLength + MAX_PIN_LENGTH)) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
      if (pins[PIN_INDEX_RC].check(buffer, ISO7816.OFFSET_CDATA, rcLength)) {
        updatePIN(PIN_INDEX_PW1, buffer, (short) (ISO7816.OFFSET_CDATA + rcLength),
                  (byte) (length - rcLength));
      } else {
        ISOException.throwIt((short) (SW_PIN_FAILED_00 + pins[PIN_INDEX_RC].getTriesRemaining()));
      }
    } else if (buffer[ISO7816.OFFSET_P1] == (byte) 2) {
      // Resetting by assuming that PW3 was submitted.
      if (!pins[PIN_INDEX_PW3].isValidated()) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      if (length < MIN_PIN1_LENGTH || length > MAX_PIN_LENGTH) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
      updatePIN(PIN_INDEX_PW1, buffer, ISO7816.OFFSET_CDATA, (byte) length);
    } else {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
  }

  /**
   * GET DATA APDU implementation. The spec isn't clear about which DOs are readable individually so
   * more tags are readable than strictly necessary.
   */
  private void getData(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short tag = Util.getShort(buffer, ISO7816.OFFSET_P1);
    short offset = 0;
    switch (tag) {
      case 0x4F:
        // Return the AID
        offset = JCSystem.getAID().getBytes(buffer, (short) 0);
        break;

      case 0x5B:
        offset = Util.arrayCopyNonAtomic(name, (short) 1, buffer, (short) 0,
                                         (short) (name[0] & 0xFF));
        break;

      case 0x5E:
        offset = Util.arrayCopyNonAtomic(loginData, (short) 1, buffer, (short) 0,
                                         (short) (loginData[0] & 0xFF));
        break;

      case 0x5F2D:
        offset = Util.arrayCopyNonAtomic(language, (short) 1, buffer, (short) 0,
                                         (short) (language[0] & 0xFF));
        break;

      case 0x5F35:
        buffer[0] = sex[0];
        offset = 1;
        break;

      case 0x5F50:
        offset = Util.arrayCopyNonAtomic(url, (short) 1, buffer, (short) 0,
                                         (short) (url[0] & 0xFF));
        break;

      case 0x5F52:
        offset = Util.arrayCopyNonAtomic(historicalBytes, (short) 0, buffer, (short) 0,
                                         (short) historicalBytes.length);
        break;

      // Cardholder related.
      case 0x65:
        buffer[0] = 0x5B;
        buffer[1] = name[0];
        offset = Util.arrayCopyNonAtomic(name, (short) 1, buffer, (short) 2,
                                         (short) (name[0] & 0xFF));

        buffer[offset++] = 0x5F;
        buffer[offset++] = 0x2D;
        buffer[offset++] = language[0];
        offset = Util.arrayCopyNonAtomic(language, (short) 1, buffer, offset,
                                         (short) (language[0] & 0xFF));

        buffer[offset++] = 0x5F;
        buffer[offset++] = 0x35;
        buffer[offset++] = 1;
        buffer[offset++] = sex[0];
        break;

      // Application related data.
      case 0x6E:
        buffer[0] = 0x4F;
        buffer[1] = JCSystem.getAID().getBytes(buffer, (short) 2);
        offset = (short) (2 + buffer[1]);

        offset = addShortTLV((short) 0x5F52, historicalBytes, buffer, offset);

        buffer[offset++] = (byte) 0x73;
        buffer[offset++] = (byte) 0x81;  // We need a two byte length.
        short oldpos = offset;
        offset = addDiscretionaryDataObjects(buffer, (short) (offset + 1));
        buffer[oldpos] = (byte) (offset - oldpos - 1);
        break;

      case 0x73:
        offset = addDiscretionaryDataObjects(buffer, (short) 0);
        break;

      case 0x7A:
        offset = addShortTLV((short) 0x93, signatureCounter, buffer, offset);
        break;

      case 0x93:
        offset = Util.arrayCopyNonAtomic(signatureCounter, (short) 0, buffer, (short) 0,
                                         (short) signatureCounter.length);
        break;

      case 0xC0:
        offset = Util.arrayCopyNonAtomic(extendedCapabilities, (short) 0, buffer, (short) 0,
                                         (short) extendedCapabilities.length);
        break;

      case 0xC1:
      case 0xC2:
      case 0xC3:
        offset = Util.arrayCopyNonAtomic(algorithmAttributes, (short) 0, buffer, (short) 0,
                                         (short) algorithmAttributes.length);
        break;

      case 0xC4:
        offset = getPWStatusBytes(buffer, (short) 0);
        break;

      case 0xC5:
        offset = Util.arrayCopyNonAtomic(fingerprints, (short) 0, buffer, (short) 0,
                                         (short) fingerprints.length);
        break;

      case 0xC6:
        offset = Util.arrayCopyNonAtomic(caFingerprints, (short) 0, buffer, (short) 0,
                                         (short) caFingerprints.length);
        break;

      case 0xCD:
        offset = Util.arrayCopyNonAtomic(generationDates, (short) 0, buffer, (short) 0,
                                         (short) generationDates.length);
        break;

      // Private use objects.
      case 0x101:
        offset = Util.arrayCopyNonAtomic(privateDO1, (short) 1, buffer, (short) 0,
                                         (short) (privateDO1[0] & 0xFF));
        break;
      case 0x102:
        offset = Util.arrayCopyNonAtomic(privateDO2, (short) 1, buffer, (short) 0,
                                         (short) (privateDO2[0] & 0xFF));
        break;

      case 0x103:
        if (!pins[PIN_INDEX_PW1].isValidated()) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        offset = Util.arrayCopyNonAtomic(privateDO3, (short) 1, buffer, (short) 0,
                                         (short) (privateDO3[0] & 0xFF));
        break;

      case 0x104:
        if (!pins[PIN_INDEX_PW3].isValidated()) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        offset = Util.arrayCopyNonAtomic(privateDO4, (short) 1, buffer, (short) 0,
                                         (short) (privateDO4[0] & 0xFF));
        break;

      default:
        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
    apdu.setOutgoingAndSend((short) 0, offset);

  }

  /**
   * Append the composite 'Discretionary Data Objetcs' DO (Tag = 0x73)
   *
   * @param out    the destination buffer.
   * @param offset the offset at which the data should be written.
   * @return the next byte that should be written
   */
  private short addDiscretionaryDataObjects(byte[] out, short offset) {
    offset = addShortTLV((short) 0xC0, extendedCapabilities, out, offset);
    for (short i = (short) 0; i < (short) 3; ++i) {
      offset = addShortTLV((short) (0xC1 + i), algorithmAttributes, out, offset);
    }
    out[offset++] = (byte) 0xC4;
    out[offset++] = 7;
    getPWStatusBytes(out, offset);
    offset += 7;

    offset = addShortTLV((short) 0xC5, fingerprints, out, offset);
    offset = addShortTLV((short) 0xC6, caFingerprints, out, offset);
    offset = addShortTLV((short) 0xCD, generationDates, out, offset);
    return offset;
  }

  /**
   * Return the PIN statuses as needed by the C4 DO.
   *
   * @param out    the destination buffer.
   * @param offset the offset at which the data should be written.
   * @return the next byte that should be written
   */
  private short getPWStatusBytes(byte[] out, short offset) {
    // 0: 00 PW1 valid for one command, 01 PW1 valid for several commands.
    out[offset++] = pinValidForMultipleSignatures;
    // 1: max length of PW1.
    out[offset++] = MAX_PIN_LENGTH;
    // 2: max length of Reseting Code.
    out[offset++] = MAX_PIN_LENGTH;
    // 3: max length of PW3
    out[offset++] = MAX_PIN_LENGTH;
    // 4, 5, 6: current try counts for PW1, RC, PW3
    out[offset++] = pins[PIN_INDEX_PW1].getTriesRemaining();
    if (pinLength[PIN_INDEX_RC] > 0) {
      out[offset++] = pins[PIN_INDEX_RC].getTriesRemaining();
    } else {
      out[offset++] = 0;
    }
    out[offset++] = pins[PIN_INDEX_PW3].getTriesRemaining();
    return offset;
  }

  /**
   * Append a fixed length byte buffer as a TLV
   *
   * @param src    the source data, must be <= 127 bytes
   * @param out    the destination for the tlv
   * @param offset the offset into out
   * @return the offset to the next byte to be written
   */
  private short addShortTLV(short tag, byte[] src, byte[] out, short offset) {
    if ((short) (tag & (short) 0xFF00) != (short) 0) {
      Util.setShort(out, offset, tag);
      offset += 2;
    } else {
      out[offset++] = (byte) tag;
    }
    out[offset++] = (byte) src.length;
    return Util.arrayCopyNonAtomic(src, (short) 0, out, offset, (short) src.length);
  }

  /**
   * The PUT DATA APDU implementation.
   */
  private void putData(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
    short tag = Util.getShort(buffer, ISO7816.OFFSET_P1);
    switch (tag) {
      // Private use objects.
      case 0x101:
        storeVariableLength(apdu, privateDO1, PIN_INDEX_PW1);
        break;

      case 0x102:
        storeVariableLength(apdu, privateDO2, PIN_INDEX_PW3);
        break;

      case 0x103:
        storeVariableLength(apdu, privateDO3, PIN_INDEX_PW1);
        break;

      case 0x104:
        storeVariableLength(apdu, privateDO4, PIN_INDEX_PW3);
        break;

      case 0x5B:
        storeVariableLength(apdu, name, PIN_INDEX_PW3);
        break;

      case 0x5E:
        storeVariableLength(apdu, loginData, PIN_INDEX_PW3);
        break;

      case 0x5F2D:
        storeVariableLength(apdu, language, PIN_INDEX_PW3);
        break;

      case 0x5F35:
        storeFixedLength(apdu, sex, (short) 0, (short) 1);
        break;

      case 0x5F50:
        storeVariableLength(apdu, url, PIN_INDEX_PW3);
        break;

      case 0xC4:
        if (!pins[PIN_INDEX_PW3].isValidated()) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (length < (short) 1 || length > (short) 8 || length != apdu.setIncomingAndReceive()) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        pinValidForMultipleSignatures = buffer[ISO7816.OFFSET_CDATA];
        break;

      case 0xC7:
      case 0xC8:
      case 0xC9:
        storeFixedLength(apdu, fingerprints, (short) (20 * (tag - 0xC7)), (short) 20);
        break;

      case 0xCA:
      case 0xCB:
      case 0xCC:
        storeFixedLength(apdu, caFingerprints, (short) (20 * (tag - 0xCA)), (short) 20);
        break;

      case 0xCE:
      case 0xCF:
      case 0xD0:
        storeFixedLength(apdu, generationDates, (short) (4 * (tag - 0xCE)), (short) 4);
        break;

      case 0xD3:
        storeVariableLength(apdu, buffer, PIN_INDEX_PW3);
        // Reset code must be zero or 8 - MAX_PIN_LENGTH.
        if (length > MAX_PIN_LENGTH || (length != (byte) 0 && length < (byte) 8)) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        updatePIN(PIN_INDEX_RC, buffer, (short) 1, buffer[0]);
        break;

      default:
        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
  }

  /**
   * Store the incoming APDU data in a fixed buffer, the first byte will contain the data length.
   *
   * @param pin_type indicates which PIN should be checked.
   */
  void storeVariableLength(APDU apdu, byte[] destination, short pin_type) {
    byte[] buffer = apdu.getBuffer();
    // When writing DOs, PW1 really means PW1 submitted as PW2.
    if (!pins[pin_type].isValidated() ||
        ((pin_type == PIN_INDEX_PW1) && !pinSubmitted[1])) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
    if ((short) (length + 1) > destination.length || length > (short) 255 ||
        apdu.setIncomingAndReceive() != length) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    JCSystem.beginTransaction();
    destination[0] = (byte) length;
    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, destination, (short) 1, length);
    JCSystem.commitTransaction();
  }

  /**
   * Store the fixed length incoming APDU data in a buffer. If the APDU data length is less than the
   * maximum length, the data will be padded with zeroes.
   */
  void storeFixedLength(APDU apdu, byte[] destination, short offset, short maximum_length) {
    byte[] buffer = apdu.getBuffer();
    // When writing DOs, PW1 really means PW1 submitted as PW2.
    if (!pins[PIN_INDEX_PW3].isValidated()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
    if (length > maximum_length || apdu.setIncomingAndReceive() != length) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, destination, offset, length);
    if (maximum_length > length) {
      Util.arrayFillNonAtomic(destination, (short) (offset + length),
                              (short) (maximum_length - length), (byte) 0);
    }
  }


  // Initialize a key part and return the offset to the next byte that should be used.
  private short addKeyPart(byte part, byte[] data, short offset, KeyPair key) {
    short size = Util.getShort(commandChainingBuffer, TEMP_PUT_KEY_EXPECTED_CHUNK_SIZE);
    short nextSize = RSA_KEY_HALF_LENGTH_BYTES;
    switch (part) {
      case KEY_PART_E:
        ((RSAPublicKey) key.getPublic()).setExponent(data, offset, size);
        break;
      case KEY_PART_PRIME_P:
        ((RSAPrivateCrtKey) key.getPrivate()).setP(data, offset, size);
        break;
      case KEY_PART_PRIME_Q:
        ((RSAPrivateCrtKey) key.getPrivate()).setQ(data, offset, size);
        break;
      case KEY_PART_PARAM_PQ:
        ((RSAPrivateCrtKey) key.getPrivate()).setPQ(data, offset, size);
        break;
      case KEY_PART_PARAM_DP1:
        ((RSAPrivateCrtKey) key.getPrivate()).setDP1(data, offset, size);
        break;
      case KEY_PART_PARAM_DQ1:
        ((RSAPrivateCrtKey) key.getPrivate()).setDQ1(data, offset, size);
        nextSize = RSA_KEY_LENGTH_BYTES;
        break;

      case KEY_PART_N:
        ((RSAPublicKey) key.getPublic()).setModulus(data, offset, RSA_KEY_LENGTH_BYTES);
        if (!key.getPrivate().isInitialized() ||
            !key.getPublic().isInitialized()) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return (short) (offset + RSA_KEY_LENGTH_BYTES);
    }
    Util.setShort(commandChainingBuffer, TEMP_PUT_KEY_EXPECTED_CHUNK_SIZE, nextSize);
    return (short) (offset + size);
  }

  private KeyPair getKey(byte type) {
    switch (type) {
      case (byte) 0xB6:
        return signatureKey;
      case (byte) 0xB8:
        return confidentialityKey;
      case (byte) 0xA4:
        return authenticationKey;
    }
    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    return signatureKey;  // Make the compiler happy.
  }

  private short addKeyPart(byte[] data, short offset) {
    return addKeyPart(commandChainingBuffer[TEMP_PUT_KEY_KEY_CHUNK], data, offset,
                      getKey(commandChainingBuffer[TEMP_PUT_KEY_KEY_TYPE]));
  }

  /**
   * PUT KEY APDU implementation.
   */
  private void putKey(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    if (!pins[PIN_INDEX_PW3].isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    short endPos = (short) (ISO7816.OFFSET_CDATA + apdu.setIncomingAndReceive());
    short pos;
    boolean firstCommand = (commandChainingBuffer[TEMP_INS] != buffer[ISO7816.OFFSET_INS]);
    // Mark the command chain as bad so it stays in this state in case of exception.
    commandChainingBuffer[TEMP_INS] = 0;
    if (firstCommand) {
      // First command, we expect at least all the TLV template and the public exponent.
      if (endPos < (short) (ISO7816.OFFSET_CDATA + expectedRSAKeyImportFormat.length)) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
      Util.arrayFillNonAtomic(commandChainingBuffer, (short) 0,
                              (short) commandChainingBuffer.length, (byte) 0);
      commandChainingBuffer[TEMP_PUT_KEY_KEY_TYPE] = buffer[(short) (ISO7816.OFFSET_CDATA + 4)];
      commandChainingBuffer[TEMP_PUT_KEY_EXPECTED_CHUNK_SIZE] = 0;
      // Copy the exponent length, all the other sizes are fixed by the RSA key length.
      byte eLength = commandChainingBuffer[(short) (TEMP_PUT_KEY_EXPECTED_CHUNK_SIZE + 1)] =
          buffer[(short) (ISO7816.OFFSET_CDATA + 10)];

      // Adjust the APDU passed as if it had CRT = 0, length of e = 0 so we can compare
      // to our canned value.
      buffer[(short) (ISO7816.OFFSET_CDATA + 4)] = 0;
      buffer[(short) (ISO7816.OFFSET_CDATA + 10)] = 0;
      // Adjust Tag 4D length
      Util.setShort(buffer, (short) (ISO7816.OFFSET_CDATA + 2),
                    (short) (Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 2)) - eLength));
      // Adjust Tag 5F48 length
      Util.setShort(buffer, (short) (ISO7816.OFFSET_CDATA + 33),
                    (short) (Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 33)) - eLength));

      if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, expectedRSAKeyImportFormat, (short) 0,
                            (short) expectedRSAKeyImportFormat.length) != 0) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      pos = (short) (ISO7816.OFFSET_CDATA + expectedRSAKeyImportFormat.length);
      // Clear the existing key.
      JCSystem.beginTransaction();
      KeyPair key = getKey(commandChainingBuffer[TEMP_PUT_KEY_KEY_TYPE]);
      key.getPrivate().clearKey();
      key.getPublic().clearKey();
      if (commandChainingBuffer[TEMP_PUT_KEY_KEY_TYPE] == (byte) 0xB6) {
        // Reset the signature counter.
        signatureCounter[0] = (byte) 0;
        signatureCounter[1] = (byte) 0;
        signatureCounter[2] = (byte) 0;
      }
      JCSystem.commitTransaction();

      commandChainingBuffer[TEMP_PUT_KEY_KEY_CHUNK] = KEY_PART_E;
    } else {
      // Chained command.
      pos = ISO7816.OFFSET_CDATA;
    }

    short accumulatorLength = Util.getShort(commandChainingBuffer, TEMP_PUT_KEY_ACCUMULATOR_LENGTH);
    for (; commandChainingBuffer[TEMP_PUT_KEY_KEY_CHUNK] <= KEY_PART_N; ) {
      short left = (short) (endPos - pos);
      short sizeNeeded = Util.getShort(commandChainingBuffer, TEMP_PUT_KEY_EXPECTED_CHUNK_SIZE);
      if (accumulatorLength != 0) {
        // There was a partial chunk left from the previous APDU, add the new data to get a
        // complete key part in commandChainingBuffer.
        short bytesToAdd;
        if ((short) (left + accumulatorLength) > sizeNeeded) {
          bytesToAdd = (short) (sizeNeeded - accumulatorLength);
        } else {
          bytesToAdd = left;
        }
        Util.arrayCopyNonAtomic(buffer, pos, commandChainingBuffer,
                                (short) (accumulatorLength + TEMP_PUT_KEY_ACCUMULATOR),
                                bytesToAdd);
        accumulatorLength += bytesToAdd;
        if (accumulatorLength == sizeNeeded) {
          addKeyPart(commandChainingBuffer, TEMP_PUT_KEY_ACCUMULATOR);
          Util.setShort(commandChainingBuffer, TEMP_PUT_KEY_ACCUMULATOR_LENGTH, (short) 0);
          accumulatorLength = 0;
        } else {
          // We need an extra APDU with more data.
          Util.setShort(commandChainingBuffer, TEMP_PUT_KEY_ACCUMULATOR_LENGTH, accumulatorLength);
          commandChainingBuffer[TEMP_INS] = CMD_PUT_KEY;
          return;
        }
        pos += bytesToAdd;
      } else {
        if (left < sizeNeeded) {
          // Not enough data, store what we have.
          Util.arrayCopyNonAtomic(buffer, pos, commandChainingBuffer, TEMP_PUT_KEY_ACCUMULATOR,
                                  left);
          Util.setShort(commandChainingBuffer, TEMP_PUT_KEY_ACCUMULATOR_LENGTH, left);
          // We need an extra APDU with more data.
          commandChainingBuffer[TEMP_INS] = CMD_PUT_KEY;
          return;
        } else {
          pos = addKeyPart(buffer, pos);
        }
      }
      commandChainingBuffer[TEMP_PUT_KEY_KEY_CHUNK]++;
    }
    // The loop only terminates when the whole key is imported and verified.
  }

  /**
   * GET CHALLENGE APDU implementation.
   */
  private void getChallenge(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
    if (length == (short) 0) {
      length = (short) 256;
    }
    randomData.generateData(buffer, (short) 0, length);
    apdu.setOutgoingAndSend((short) 0, length);
  }

  private void computeSignature(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short length = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
    // Make sure that DigestInfo is <= 40% of the RSA key length.
    if ((short) (length * 4) > (short) (RSA_KEY_LENGTH_BYTES * 10) ||
        apdu.setIncomingAndReceive() != length) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (!pinSubmitted[PIN_INDEX_PW1] || !pins[PIN_INDEX_PW1].isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (!signatureKey.getPrivate().isInitialized()) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }
    if (pinValidForMultipleSignatures == (byte) 0) {
      pinSubmitted[PIN_INDEX_PW1] = false;
    }

    cipherRSA.init(signatureKey.getPrivate(), Cipher.MODE_ENCRYPT);
    cipherRSA.doFinal(buffer, ISO7816.OFFSET_CDATA, length, buffer, (short) 0);
    JCSystem.beginTransaction();
    if (signatureCounter[2] != (byte) 0xFF) {
      signatureCounter[2] = (byte) ((signatureCounter[2] & 0xFF) + 1);
    } else {
      signatureCounter[2] = 0;
      if (signatureCounter[1] != (byte) 0xFF) {
        signatureCounter[1] = (byte) ((signatureCounter[1] & 0xFF) + 1);
      } else if (signatureCounter[0] != (byte) 0xFF) {
        signatureCounter[1] = 0;
        signatureCounter[0] = (byte) ((signatureCounter[0] & 0xFF) + 1);
      } else {
        JCSystem.abortTransaction();
        ISOException.throwIt(ISO7816.SW_FILE_FULL);
      }
    }
    JCSystem.commitTransaction();
    apdu.setOutgoingAndSend((short) 0, RSA_KEY_LENGTH_BYTES);
  }

  private void decrypt(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    // PW1 with 0x82
    if (!pins[PIN_INDEX_PW1].isValidated() || !pinSubmitted[1]) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (!confidentialityKey.getPrivate().isInitialized()) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }
    boolean firstCommand = (commandChainingBuffer[TEMP_INS] != buffer[ISO7816.OFFSET_INS]);
    // Mark the command chain as bad so it stays in this state in case of exception.
    short len = apdu.setIncomingAndReceive();
    if (len < 1) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (firstCommand) {
      Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA + 1), commandChainingBuffer,
                              TEMP_GET_RESPONSE_DATA, (short) (len - 1));
      len = (short) (len - 1);
    } else {
      short existing = Util.getShort(commandChainingBuffer, TEMP_GET_RESPONSE_LENGTH);
      if ((short) (len + existing) > RSA_KEY_LENGTH_BYTES) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
      Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, commandChainingBuffer,
                              (short) (TEMP_GET_RESPONSE_DATA + existing), len);
      len += existing;
    }
    if (len < RSA_KEY_LENGTH_BYTES) {
      commandChainingBuffer[TEMP_INS] = CMD_COMPUTE_PSO;
      Util.setShort(commandChainingBuffer, TEMP_GET_RESPONSE_LENGTH, len);
      return;  // For compatibily with GPG
    }
    // We have enough bytes to decrypt.
    cipherRSA.init(confidentialityKey.getPrivate(), Cipher.MODE_DECRYPT);
    len = cipherRSA.doFinal(commandChainingBuffer, TEMP_GET_RESPONSE_DATA, RSA_KEY_LENGTH_BYTES,
                            buffer, (short) 0);
    apdu.setOutgoingAndSend((short) 0, len);
  }

  private void internalAuthenticate(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    // PW1 with 0x82
    if (!pins[PIN_INDEX_PW1].isValidated() || !pinSubmitted[1]) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short len = apdu.setIncomingAndReceive();
    if (len > (short) 102 || len != (buffer[ISO7816.OFFSET_LC] & 0xFF)) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (!authenticationKey.getPrivate().isInitialized()) {
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }
    cipherRSA.init(authenticationKey.getPrivate(), Cipher.MODE_ENCRYPT);
    cipherRSA.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);
    apdu.setOutgoingAndSend((short) 0, RSA_KEY_LENGTH_BYTES);
  }

  /**
   * GENERATE KEY APDU implementation.
   */
  private void generateAsymetricKey(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    if (apdu.setIncomingAndReceive() != 2) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    KeyPair key = getKey(buffer[ISO7816.OFFSET_CDATA]);
    if (buffer[ISO7816.OFFSET_P1] == (byte) 0x81) {
      if (!(key.getPublic()).isInitialized()) {
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      }
    } else {
      if (!pins[PIN_INDEX_PW3].isValidated()) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      JCSystem.beginTransaction();
      key.genKeyPair();
      if (buffer[ISO7816.OFFSET_CDATA] == (byte)0xB6) {
        signatureCounter[0] = 0;
        signatureCounter[1] = 0;
        signatureCounter[2] = 0;
      }
      JCSystem.commitTransaction();
    }
    // Send the TLV data and public exponent using the APDU buffer.
    buffer[ISO7816.OFFSET_CDATA] = 0x7F;
    buffer[(short) (ISO7816.OFFSET_CDATA + 1)] = 0x49;
    buffer[(short) (ISO7816.OFFSET_CDATA + 2)] = (byte) 0x82;
    buffer[(short) (ISO7816.OFFSET_CDATA + 5)] = (byte) 0x82;
    short length = ((RSAPublicKey) key.getPublic()).getExponent(
        buffer, (short) (ISO7816.OFFSET_CDATA + 7));
    buffer[(short) (ISO7816.OFFSET_CDATA + 6)] = (byte) length;
    short pos = (short) (ISO7816.OFFSET_CDATA + 7 + length);
    buffer[pos] = (byte) 0x81;
    buffer[(short) (pos + 1)] = (byte) 0x82;
    Util.setShort(buffer, (short) (pos + 2), RSA_KEY_LENGTH_BYTES);
    Util.setShort(buffer, (short) (ISO7816.OFFSET_CDATA + 3),
                  (short) (pos + RSA_KEY_LENGTH_BYTES - ISO7816.OFFSET_CDATA - 1));
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (length + 11));

    // And the modulus using get response.
    Util.setShort(commandChainingBuffer, TEMP_GET_RESPONSE_LENGTH, RSA_KEY_LENGTH_BYTES);
    ((RSAPublicKey) key.getPublic()).getModulus(commandChainingBuffer, TEMP_GET_RESPONSE_DATA);
    // Skip leading zero byte.
    if (commandChainingBuffer[TEMP_GET_RESPONSE_DATA] == 0) {
      Util.setShort(commandChainingBuffer, TEMP_GET_RESPONSE_OFFSET,
                    (short) (TEMP_GET_RESPONSE_DATA + 1));
    } else {
      Util.setShort(commandChainingBuffer, TEMP_GET_RESPONSE_OFFSET, TEMP_GET_RESPONSE_DATA);
    }
    commandChainingBuffer[TEMP_INS] = buffer[ISO7816.OFFSET_INS];
    ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
  }

  /**
   * Terminate DF is only valid if PW1 and PW3 are blocked.
   * @param apdu
   */
  private void terminateDF(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    if (buffer[ISO7816.OFFSET_LC] != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (pins[PIN_INDEX_PW1].getTriesRemaining() > 0 ||
        pins[PIN_INDEX_PW3].getTriesRemaining() > 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    terminated = true;
  }

  /**
   * ACTIVATE FILE does nothing if the card is not in the 'initialization' state (really if it
   * hasn't been terminated).
   * @param apdu
   */
  private void activateFile(APDU apdu) {
    if (!terminated) {
      return;
    }

    // Since the card will not do anything until we clear the terminated bool we can erase the
    // data without using transactions (and most likely the transaction buffer would not be
    // large enough.
    signatureKey.getPrivate().clearKey();
    signatureKey.getPublic().clearKey();
    confidentialityKey.getPrivate().clearKey();
    confidentialityKey.getPublic().clearKey();
    authenticationKey.getPrivate().clearKey();
    authenticationKey.getPublic().clearKey();

    pins[PIN_INDEX_PW1].update(defaultPIN, (short) 0, MIN_PIN1_LENGTH);
    pinLength[PIN_INDEX_PW1] = MIN_PIN1_LENGTH;
    pins[PIN_INDEX_PW3].update(defaultPIN, (short) 0, MIN_PIN3_LENGTH);
    pinLength[PIN_INDEX_PW3] = MIN_PIN3_LENGTH;
    // The resetting code is disabled by default.
    pinLength[PIN_INDEX_RC] = 0;

    Util.arrayFillNonAtomic(privateDO1, (short)0, (short)privateDO1.length, (byte)0);
    Util.arrayFillNonAtomic(privateDO2, (short)0, (short)privateDO2.length, (byte)0);
    Util.arrayFillNonAtomic(privateDO3, (short)0, (short)privateDO3.length, (byte)0);
    Util.arrayFillNonAtomic(privateDO4, (short)0, (short)privateDO4.length, (byte)0);

    Util.arrayFillNonAtomic(loginData, (short)0, (short)loginData.length, (byte)0);
    Util.arrayFillNonAtomic(url, (short)0, (short)url.length, (byte)0);
    Util.arrayFillNonAtomic(name, (short)0, (short)name.length, (byte)0);
    Util.arrayFillNonAtomic(language, (short)0, (short)language.length, (byte)0);
    sex[0] = 0;
    Util.arrayFillNonAtomic(fingerprints, (short)0, (short)fingerprints.length, (byte)0);
    Util.arrayFillNonAtomic(caFingerprints, (short)0, (short)caFingerprints.length, (byte)0);
    Util.arrayFillNonAtomic(generationDates, (short)0, (short)generationDates.length, (byte)0);
    Util.arrayFillNonAtomic(signatureCounter, (short)0, (short)signatureCounter.length, (byte)0);
    pinValidForMultipleSignatures = (byte) 0;
    terminated = false;
  }
}

