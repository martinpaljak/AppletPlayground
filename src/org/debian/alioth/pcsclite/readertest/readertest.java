/*
 * This applet is used to test smart cards drivers by sending/receiving
 * ISO 7816 commands
 *
 * Authors: Jean-Luc Giraud <jlgiraud@mac.com>
 *          Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * See COPYING
 *
 * $Id$
 */

/*
 * Package name
 */
package org.debian.alioth.pcsclite.readertest;


/*
 * Imported packages
 */
// specific import for Javacard API access
import javacard.framework.*;


public class readertest extends javacard.framework.Applet
{
    private final static byte CLA_TEST_READER  = (byte)0x80;
    private final static byte INS_CASE_2_ODD   = (byte)0x21;
    private final static byte INS_CASE_3_ODD   = (byte)0x22;
    private final static byte INS_CASE_4_ODD   = (byte)0x23;
    private final static byte INS_CASE_1       = (byte)0x30;
    private final static byte INS_CASE_2       = (byte)0x32;
    private final static byte INS_CASE_3       = (byte)0x34;
    private final static byte INS_CASE_4       = (byte)0x36;
    private final static byte INS_TIME_REQUEST = (byte)0x38;
    private final static byte INS_CASE_2_UNBOUND = (byte)0x3A;
    private final static byte INS_CASE_3_UNBOUND = (byte)0x3C;
    private final static byte INS_CASE_4_UNBOUND = (byte)0x3E;
    private final static byte INS_VERIFY_PIN = (byte)0x20;
    private final static byte INS_VERIFY_PIN_DUMP = (byte)0x40;
    private final static byte INS_MODIFY_PIN = (byte)0x24;

    private final static byte pcValueTable[]  = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B, (byte) 0x8C, (byte) 0x8D, (byte) 0x8E, (byte) 0x8F,
    (byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97, (byte) 0x98, (byte) 0x99, (byte) 0x9A, (byte) 0x9B, (byte) 0x9C, (byte) 0x9D, (byte) 0x9E, (byte) 0x9F,
    (byte) 0xA0, (byte) 0xA1, (byte) 0xA2, (byte) 0xA3, (byte) 0xA4, (byte) 0xA5, (byte) 0xA6, (byte) 0xA7, (byte) 0xA8, (byte) 0xA9, (byte) 0xAA, (byte) 0xAB, (byte) 0xAC, (byte) 0xAD, (byte) 0xAE, (byte) 0xAF,
    (byte) 0xB0, (byte) 0xB1, (byte) 0xB2, (byte) 0xB3, (byte) 0xB4, (byte) 0xB5, (byte) 0xB6, (byte) 0xB7, (byte) 0xB8, (byte) 0xB9, (byte) 0xBA, (byte) 0xBB, (byte) 0xBC, (byte) 0xBD, (byte) 0xBE, (byte) 0xBF,
    (byte) 0xC0, (byte) 0xC1, (byte) 0xC2, (byte) 0xC3, (byte) 0xC4, (byte) 0xC5, (byte) 0xC6, (byte) 0xC7, (byte) 0xC8, (byte) 0xC9, (byte) 0xCA, (byte) 0xCB, (byte) 0xCC, (byte) 0xCD, (byte) 0xCE, (byte) 0xCF,
    (byte) 0xD0, (byte) 0xD1, (byte) 0xD2, (byte) 0xD3, (byte) 0xD4, (byte) 0xD5, (byte) 0xD6, (byte) 0xD7, (byte) 0xD8, (byte) 0xD9, (byte) 0xDA, (byte) 0xDB, (byte) 0xDC, (byte) 0xDD, (byte) 0xDE, (byte) 0xDF,
    (byte) 0xE0, (byte) 0xE1, (byte) 0xE2, (byte) 0xE3, (byte) 0xE4, (byte) 0xE5, (byte) 0xE6, (byte) 0xE7, (byte) 0xE8, (byte) 0xE9, (byte) 0xEA, (byte) 0xEB, (byte) 0xEC, (byte) 0xED, (byte) 0xEE, (byte) 0xEF,
    (byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF3, (byte) 0xF4, (byte) 0xF5, (byte) 0xF6, (byte) 0xF7, (byte) 0xF8, (byte) 0xF9, (byte) 0xFA, (byte) 0xFB, (byte) 0xFC, (byte) 0xFD, (byte) 0xFE, (byte) 0xFF
     };

    private byte pbMemory[];
    private short pbMemoryLength;
    private static final byte RETRY_COUNTER_MAX_VALUE = 3;
    private byte retryCounter = RETRY_COUNTER_MAX_VALUE;

    /**
     * readertest default constructor
     * Only this class's install method should create the applet object.
     */
    protected readertest(byte[] buffer, short offset, byte length)
    {
        if (buffer[offset] == 0)
            this.register();
        else
            this.register(buffer, (short)(offset + 1), buffer[offset]);

        pbMemory = new byte[256+4];
        for (short i=0; i<pbMemory.length; i++)
            pbMemory[i] = 0x42;
    }

    /**
     * Method installing the applet.
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        /* applet  instance creation */
        new readertest (bArray, bOffset, (byte)bLength );
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        // return status of selection
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {
        return;
    }

    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException
    {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();
        short bytesLeft;
        short le;
        short index;
        short readCount;

        // ignore the applet select command dispatched to the process
        if (selectingApplet())
            return;

        // APDU instruction parser
        switch ( apduBuffer[ISO7816.OFFSET_INS] )
        {
            case INS_CASE_1:
              if ( (apduBuffer[ISO7816.OFFSET_LC] & (byte) 0x00FF) != 0 )
              {
                ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
              }
              break;

            case INS_CASE_2:
            case INS_CASE_2_ODD:
              // Incoming Data length
              bytesLeft = (short) (apduBuffer[ISO7816.OFFSET_LC]
                                               & 0x00FF);
              if ( bytesLeft == 0 )
              {
                ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
              }
              // Get the Data
              index=0;
              readCount = apdu.setIncomingAndReceive();
              while ( bytesLeft > 0 )
              {
                for (short i=0; i<readCount; i++)
                {
                  if ( ((short)(apduBuffer[(short)(ISO7816.OFFSET_CDATA+i)] & 0x00FF))
                         != index )
                  {
                    short SW = (short) (0x6A00 + i);
                    ISOException.throwIt( SW );
                  }
                  index++;
                }
                bytesLeft -= readCount;
                readCount = apdu.receiveBytes (ISO7816.OFFSET_CDATA);
              }
            break;

            case INS_CASE_3:
            case INS_CASE_3_ODD:
              // Outgoing Data length
              le = apdu.setOutgoing();
              if ( le == ((short) 0x0000) )
              {
                le = (short) 0x0100;
              }
              short requiredLe = Util.getShort(apduBuffer,ISO7816.OFFSET_P1);
              //short requiredLe = (short) (apduBuffer[ISO7816.OFFSET_P1] << 8);
              //requiredLe += (short)(apduBuffer[ISO7816.OFFSET_P2]);
              if ( le != requiredLe )
              {
                ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
              }
              apdu.setOutgoingLength (le);
              apdu.sendBytesLong(pcValueTable, (short) 0x0000, le);
            break;

            case INS_CASE_4:
            case INS_CASE_4_ODD:
              // Incoming Data length
              bytesLeft = (short) (apduBuffer[ISO7816.OFFSET_LC]
                                               & 0x00FF);
              if ( bytesLeft == 0 )
              {
                ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
              }
              // Get the Data
              index=0;
              readCount = apdu.setIncomingAndReceive();
              while ( bytesLeft > 0 )
              {
                for (short i=0; i<readCount; i++)
                {
                  if ( ((short)(apduBuffer[(short)(ISO7816.OFFSET_CDATA+i)] & 0x00FF))
                         != index )
                  {
                    short SW = (short) (0x6A00 + i);
                    ISOException.throwIt( SW );
                  }
                  index++;
                }
                bytesLeft -= readCount;
                readCount = apdu.receiveBytes (ISO7816.OFFSET_CDATA);
              }
              // Outgoing Data length
              apdu.setOutgoing();
              requiredLe = Util.getShort(apduBuffer,ISO7816.OFFSET_P1);
              apdu.setOutgoingLength (requiredLe);
              apdu.sendBytesLong(pcValueTable, (short) 0x0000, requiredLe);
            break;

            case INS_TIME_REQUEST:
                short waitTime = (short) (apduBuffer[ISO7816.OFFSET_P2] &
                        0x00FF);

                for (short i=0; i<waitTime; i++)
                    for (short j=0; j<1000; j++)
                        ;

            break;

            case INS_CASE_2_UNBOUND:
              // Incoming Data length
              bytesLeft = (short) (apduBuffer[ISO7816.OFFSET_LC]
                                               & 0x00FF);
              if ( bytesLeft == 0 )
              {
                ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
              }
              // Get the Data
              index=0;
              readCount = apdu.setIncomingAndReceive();
              while ( bytesLeft > 0 )
              {
                for (short i=0; i<readCount; i++)
                {
                  if ( ((short)(apduBuffer[(short)(ISO7816.OFFSET_CDATA+i)] & 0x00FF))
                         != index )
                  {
                    short SW = (short) (0x6A00 + i);
                    ISOException.throwIt( SW );
                  }
                  index++;
                }
                bytesLeft -= readCount;
                readCount = apdu.receiveBytes (ISO7816.OFFSET_CDATA);
              }
            break;

            case INS_CASE_3_UNBOUND:
              // Outgoing Data length
              le = apdu.setOutgoing();
              requiredLe = Util.getShort(apduBuffer,ISO7816.OFFSET_P1);

              apdu.setOutgoingLength (le);
              apdu.sendBytesLong(pcValueTable, (short) 0x0000, requiredLe);
            break;

            case INS_CASE_4_UNBOUND:
              // Incoming Data length
              bytesLeft = (short) (apduBuffer[ISO7816.OFFSET_LC]
                                               & 0x00FF);
              // Get the Data
              index=0;
              readCount = apdu.setIncomingAndReceive();
              while ( bytesLeft > 0 )
              {
                for (short i=0; i<readCount; i++)
                {
                  if ( ((short)(apduBuffer[(short)(ISO7816.OFFSET_CDATA+i)] & 0x00FF))
                         != index )
                  {
                    short SW = (short) (0x6A00 + i);
                    ISOException.throwIt( SW );
                  }
                  index++;
                }
                bytesLeft -= readCount;
                readCount = apdu.receiveBytes (ISO7816.OFFSET_CDATA);
              }
              // Outgoing Data length
              requiredLe = Util.getShort(apduBuffer,ISO7816.OFFSET_P1);
              apdu.setOutgoingLength (requiredLe);
              apdu.sendBytesLong(pcValueTable, (short) 0x0000, requiredLe);
            break;

            case INS_VERIFY_PIN:
              // Memorize APDU header
              Util.arrayCopy(apduBuffer, (short)0, pbMemory, (short)0,
                  (short)5);

              // Incoming Data length
              bytesLeft = (short) (apduBuffer[ISO7816.OFFSET_LC]
                                               & 0x00FF);
              if ( bytesLeft == 0 )
              {
                // send the number of tries left
                ISOException.throwIt( (short)(0x63C0 + retryCounter) );
              }
              // Get the Data
              index=0;
              readCount = apdu.setIncomingAndReceive();

              // Memorize the command
              Util.arrayCopy(apduBuffer, (short)ISO7816.OFFSET_CDATA,
              pbMemory, (short)ISO7816.OFFSET_CDATA, (short)readCount);
              pbMemoryLength = (short)(bytesLeft+5);

              while ( bytesLeft > 0 )
              {
                for (short i=0; i<readCount; i++)
                {
                  if ( ((short)(apduBuffer[(short)(ISO7816.OFFSET_CDATA+i)] & 0x00FF))
                         != (short)(i + 0x31))
                  {
                    // decrement the retry counter
                    if (retryCounter > 0)
                        retryCounter--;

                    short SW = (short) (0x6A00 + i);
                    ISOException.throwIt( SW );
                  }
                  index++;
                }
                bytesLeft -= readCount;
                readCount = apdu.receiveBytes (ISO7816.OFFSET_CDATA);

                // reset the retry counter
                retryCounter = RETRY_COUNTER_MAX_VALUE;

                // Memorize the command
                Util.arrayCopy(apduBuffer, (short)(ISO7816.OFFSET_CDATA+index),
                    pbMemory, (short)(ISO7816.OFFSET_CDATA+index),
                    (short)readCount);
          }

            break;

            case INS_VERIFY_PIN_DUMP:
              // Outgoing Data length
              le = apdu.setOutgoing();

              apdu.setOutgoingLength (pbMemoryLength);
              apdu.sendBytesLong(pbMemory, (short)0, pbMemoryLength);
            break;

            case INS_MODIFY_PIN:
              // Memorize APDU header
              Util.arrayCopy(apduBuffer, (short)0, pbMemory, (short)0,
                  (short)5);

              // Incoming Data length
              bytesLeft = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0x00FF);
              if ( bytesLeft == 0 )
              {
                ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
              }
              // Get the Data
              index=0;
              readCount = apdu.setIncomingAndReceive();

              // Memorize the command
              Util.arrayCopy(apduBuffer, (short)ISO7816.OFFSET_CDATA,
                  pbMemory, (short)ISO7816.OFFSET_CDATA, (short)readCount);
              pbMemoryLength = (short)(bytesLeft+5);

              while ( bytesLeft > 0 )
              {
                for (short i=0; i<readCount; i++)
                {
                  if ( ((short)(apduBuffer[(short)(ISO7816.OFFSET_CDATA+i)] & 0x00FF))
                         != (short)(i + 0x31))
                  {
                    short SW = (short) (0x6A00 + i);
                    ISOException.throwIt( SW );
                  }
                  index++;
                }
                bytesLeft -= readCount;
                readCount = apdu.receiveBytes (ISO7816.OFFSET_CDATA);

                // Memorize the command
                Util.arrayCopy(apduBuffer, (short)(ISO7816.OFFSET_CDATA+index),
                    pbMemory, (short)(ISO7816.OFFSET_CDATA+index),
                    (short)readCount);
              }

            break;

            default:
                // The INS code is not supported by the dispatcher
                ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
            break ;
        }
    }
}

