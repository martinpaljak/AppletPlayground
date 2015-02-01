/*
    Copyright (c) 2004-2014  Petr Svenda <petr@svenda.com>

     LICENSE TERMS

     The free distribution and use of this software in both source and binary
     form is allowed (with or without changes) provided that:

       1. distributions of this source code include the above copyright
          notice, this list of conditions and the following disclaimer;

       2. distributions in binary form include the above copyright
          notice, this list of conditions and the following disclaimer
          in the documentation and/or other associated materials;

       3. the copyright holder's name is not used to endorse products
          built using this software without specific written permission.

     ALTERNATIVELY, provided that this notice is retained in full, this product
     may be distributed under the terms of the GNU General Public License (GPL),
     in which case the provisions of the GPL apply INSTEAD OF those given above.

     DISCLAIMER

     This software is provided 'as is' with no explicit or implied warranties
     in respect of its properties, including, but not limited to, correctness
     and/or fitness for purpose.

    Please, report any bugs to author <petr@svenda.com>
/**/

/*
 * Package AID: 6D 79 70 61 63 6B 61 67 31 (6D797061636B616731)
 * Applet AID:  6D 79 70 61 63 30 30 30 31 (6D7970616330303031)
 */
package AlgTest;

/*
 * Imported packages
 */
// specific import for Javacard API access
import AlgTest.AlgTest;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

// JC 2.2.2 only
//import javacardx.apdu.ExtendedLength; 
//public class AlgTest extends javacard.framework.Applet implements ExtendedLength 

public class AlgTestPerformance extends javacard.framework.Applet 
{
    // NOTE: when incrementing version, don't forget to update ALGTEST_JAVACARD_VERSION_CURRENT value

    /**
     * Version 1.3 (20.3.2014)
     * + Possibility to test single algorithm at single apdu command (possibility for reset in between) via TestSupportedModeSingle()
     */
    final static byte ALGTEST_JAVACARD_VERSION_1_3[] = {(byte) 0x31, (byte) 0x2e, (byte) 0x33};
    /**
     * Version 1.2 (3.11.2013)
     * + All relevant constants from JC2.2.2, JC3.0.1 & JC3.0.4 added
     * + Refactoring of exception capture (all try with two catch). Disabled at the moment due to JC conversion error:  Package contains more than 255 exception handlers.
     * + Refactoring of version reporting
     * + Fixed incorrect test during TYPE_RSA_PRIVATE_KEY of LENGTH_RSA_3072 (mistake) of instead of LENGTH_RSA_4096 (correct)
     * + Changed format of values reported in return array. Unused values are now marked as 0xf0 (change from 0x05). 
     *   Supported algorithm is now designated as 0x00 (change from 0x01). When CryptoException is thrown and captured, value of CryptoException is stored (range from 0x01-0x05). 
     */
    final static byte ALGTEST_JAVACARD_VERSION_1_2[] = {(byte) 0x31, (byte) 0x2e, (byte) 0x32};
    /**
     * Version 1.1 (28.6.2013)
     * + information about version added, command for version retrieval
     */
    final static byte ALGTEST_JAVACARD_VERSION_1_1[] = {(byte) 0x31, (byte) 0x2e, (byte) 0x31};
    /**
     * Version 1.0 (2004-2013)
     * + initial version for version-tracking enabled (all features implemented in 2004-2013)
     */
    final static byte ALGTEST_JAVACARD_VERSION_1_0[] = {(byte) 0x31, (byte) 0x2e, (byte) 0x30};

    byte ALGTEST_JAVACARD_VERSION_CURRENT[] = ALGTEST_JAVACARD_VERSION_1_1;

    
    final static byte CLA_CARD_ALGTEST               = (byte) 0xB0;
    final static byte INS_CARD_GETVERSION            = (byte) 0x60;
    final static byte INS_CARD_TESTSUPPORTEDMODES    = (byte) 0x70;
    final static byte INS_CARD_TESTAVAILABLE_MEMORY  = (byte) 0x71;
    final static byte INS_CARD_TESTRSAEXPONENTSET    = (byte) 0x72;
    final static byte INS_CARD_JCSYSTEM_INFO         = (byte) 0x73;
    final static byte INS_CARD_TESTEXTAPDU           = (byte) 0x74;
    final static byte INS_CARD_TESTSUPPORTEDMODES_SINGLE    = (byte) 0x75;

    private   Cipher           m_encryptCipher = null;
    private   Cipher           m_encryptCipherRSA = null;
    private   Signature        m_sign = null;
    private   Key              m_key = null;
    private   MessageDigest    m_digest = null;
    private   RandomData       m_random = null;
    private   Object           m_object = null;
    private   KeyPair          m_keyPair = null;
    private   byte[]           m_ramArray = null;
    private   byte[]           m_eepromArray1 = null;
    private   byte[]           m_eepromArray2 = null;
    private   byte[]           m_eepromArray3 = null;
    private   byte[]           m_eepromArray4 = null;
    private   byte[]           m_eepromArray5 = null;
    private   byte[]           m_eepromArray6 = null;
    private   byte[]           m_eepromArray7 = null;
    private   byte[]           m_eepromArray8 = null;
    private   RSAPublicKey     rsa_PublicKey = null;

    final static short EXPONENT_LENGTH = (short) 128;
    final static short MODULUS_LENGTH = (short) 128;
    final static short ADDITIONAL_ARGUMENTS_LENGTH = (short) (ISO7816.OFFSET_CDATA + 4); // two short arguments
    
    final static byte SUPP_ALG_UNTOUCHED = (byte) 0xf0;
    final static byte SUPP_ALG_SUPPORTED = (byte) 0x00;
    final static byte SUPP_ALG_EXCEPTION_CODE_OFFSET = (byte) 0;
    
    // RSA exponent
    public static final byte ALG_SECURE_RANDOM = 2;
    public static final byte ALG_RSA_NOPAD = 12;

    /**
     * AlgTest default constructor
     * Only this class's install method should create the applet object.
     */
    protected AlgTestPerformance(byte[] buffer, short offset, byte length)
    {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]

            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

            // go to proprietary data
            dataOffset++;

            // update flag
            isOP2 = true;

        } else {
       }

        if (isOP2) { register(buffer, (short)(offset + 1), (byte)buffer[offset]); }
        else { register(); }
    }

    /**
     * Method installing the applet.
     * @param bArray the array constaining installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        /* applet  instance creation */
        new AlgTestPerformance (bArray, bOffset, (byte)bLength );
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {

        // <PUT YOUR DESELECTION ACTION HERE>
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

        // ignore the applet select command dispached to the process
        if (selectingApplet()) { return; }

        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_CARD_ALGTEST) {
            switch ( apduBuffer[ISO7816.OFFSET_INS]) {
                case INS_CARD_GETVERSION: GetVersion(apdu); break;
                case INS_CARD_TESTAVAILABLE_MEMORY: TestAvailableMemory(apdu); break;
                case INS_CARD_TESTRSAEXPONENTSET: TestRSAExponentSet(apdu); break;
                case INS_CARD_JCSYSTEM_INFO: JCSystemInfo(apdu); break;
                case INS_CARD_TESTEXTAPDU: TestExtendedAPDUSupport(apdu); break;

                default : {
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INCORRECT_P1P2  ) ;
                    break;
                }
            }
        }
    }

    void GetVersion(APDU apdu) {
        byte[]    apdubuf = apdu.getBuffer();

        Util.arrayCopyNonAtomic(ALGTEST_JAVACARD_VERSION_CURRENT, (short) 0, apdubuf, (short) 0, (short) ALGTEST_JAVACARD_VERSION_CURRENT.length);

        apdu.setOutgoingAndSend((byte) 0, (short) ALGTEST_JAVACARD_VERSION_CURRENT.length);
    }

   void TestAvailableMemory(APDU apdu) {
       byte[]    apdubuf = apdu.getBuffer();
       short     dataLen = apdu.setIncomingAndReceive();
       short     offset = (short) 0;

       short     toAllocateRAM = (short) 30000;
       if (apdubuf[ISO7816.OFFSET_P1] == 0x00) {
           if (m_ramArray == null) {
             while (true) {
               if (toAllocateRAM < 20) { break; }
               try {
                 m_ramArray = JCSystem.makeTransientByteArray(toAllocateRAM, JCSystem.CLEAR_ON_DESELECT);
                 // ALLOCATION WAS SUCESSFULL
                 break;
               }
               catch (Exception e) {
                 // DECREASE TESTED ALLOCATION LENGTH BY 1%
                 toAllocateRAM = (short) (toAllocateRAM - (short) (toAllocateRAM / 100));
               }
             }
           }
           else {
             // ARRAY ALREADY ALLOCATED, JUST RETURN ITS LENGTH
             toAllocateRAM = (short) m_ramArray.length;
           }
       }
       Util.setShort(apdubuf, offset, toAllocateRAM);
       offset = (short)(offset + 2);
       //
       // EEPROM TEST
       //
       if (apdubuf[ISO7816.OFFSET_P1] == 0x01) {
         short     toAllocateEEPROM = (short) 15000;    // at maximum 15KB allocated into single array 
         if (m_eepromArray1 == null) {
           while (true) {
             if (toAllocateEEPROM < 100) { break; } // We will stop when less then 100 remain to be allocated
             try {
               if (m_eepromArray1 == null) { m_eepromArray1 = new byte[toAllocateEEPROM]; }
               if (m_eepromArray2 == null) { m_eepromArray2 = new byte[toAllocateEEPROM]; }
               if (m_eepromArray3 == null) { m_eepromArray3 = new byte[toAllocateEEPROM]; }
               if (m_eepromArray4 == null) { m_eepromArray4 = new byte[toAllocateEEPROM]; }
               if (m_eepromArray5 == null) { m_eepromArray5 = new byte[toAllocateEEPROM]; }
               if (m_eepromArray6 == null) { m_eepromArray6 = new byte[toAllocateEEPROM]; }
               if (m_eepromArray7 == null) { m_eepromArray7 = new byte[toAllocateEEPROM]; }
               if (m_eepromArray8 == null) { m_eepromArray8 = new byte[toAllocateEEPROM]; }
               // ALLOCATION OF ALL ARRAYS WAS SUCESSFULL

               break;
             }
             catch (Exception e) {
               // DECREASE TESTED ALLOCATION LENGTH BY 10%
               toAllocateEEPROM = (short) (toAllocateEEPROM - (short) (toAllocateEEPROM / 10));
             }
           }
         }
         else {
           // ARRAY(s) ALREADY ALLOCATED, JUST RETURN THEIR COMBINED LENGTH
         }

         if (m_eepromArray1 != null) { Util.setShort(apdubuf, offset, (short) m_eepromArray1.length); }
         else { Util.setShort(apdubuf, offset, (short) 0); }
         offset = (short)(offset + 2); 
         if (m_eepromArray2 != null) { Util.setShort(apdubuf, offset, (short) m_eepromArray2.length); }
         else { Util.setShort(apdubuf, offset, (short) 0); }
         offset = (short)(offset + 2);
         if (m_eepromArray3 != null) { Util.setShort(apdubuf, offset, (short) m_eepromArray3.length); }
         else { Util.setShort(apdubuf, offset, (short) 0); }
         offset = (short)(offset + 2);
         if (m_eepromArray4 != null) { Util.setShort(apdubuf, offset, (short) m_eepromArray4.length); }
         else { Util.setShort(apdubuf, offset, (short) 0); }
         offset = (short)(offset + 2);
         if (m_eepromArray5 != null) { Util.setShort(apdubuf, offset, (short) m_eepromArray5.length); }
         else { Util.setShort(apdubuf, offset, (short) 0); }
         offset = (short)(offset + 2);
         if (m_eepromArray6 != null) { Util.setShort(apdubuf, offset, (short) m_eepromArray6.length); }
         else { Util.setShort(apdubuf, offset, (short) 0); }
         offset = (short)(offset + 2);
         if (m_eepromArray7 != null) { Util.setShort(apdubuf, offset, (short) m_eepromArray7.length); }
         else { Util.setShort(apdubuf, offset, (short) 0); }
         offset = (short)(offset + 2);
         if (m_eepromArray8 != null) { Util.setShort(apdubuf, offset, (short) m_eepromArray8.length); }
         else { Util.setShort(apdubuf, offset, (short) 0); }
         offset = (short)(offset + 2);
/**/
       }
       apdu.setOutgoingAndSend((short) 0, (short) (offset));
   }

   /**
    * Note - Whole process is differentiated into separate steps to distinguish
    * between different situation when random exponent cannot be set.
    * E.g. Some cards allow to set random exponent, but throw Exception when public key
    * is used for encryption (rsa_PublicKey.setExponent). Other cards fail directly
    * during exponent setting (rsa_PublicKey.setExponent). One card (PalmeraV5) successfully
    * passed all steps, but didn't returned encrypted data (resp. length of returned
    * data was 0 and status 90 00)
    */
   void TestRSAExponentSet(APDU apdu) {
       byte[]    apdubuf = apdu.getBuffer();
       short     dataLen = apdu.setIncomingAndReceive();

       switch (apdubuf[ISO7816.OFFSET_P1]) {
         case 1: {
           // Allocate objects if not allocated yet
           if (rsa_PublicKey == null) { rsa_PublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_1024,false); }
           if (m_random == null) { m_random = RandomData.getInstance(ALG_SECURE_RANDOM); } 
           if (m_encryptCipherRSA == null) { m_encryptCipherRSA = Cipher.getInstance(ALG_RSA_NOPAD, false); }
           break;
         }
         case 2: {
           // Try to set random modulus
           m_random.generateData(apdubuf, ISO7816.OFFSET_CDATA, MODULUS_LENGTH);
           rsa_PublicKey.setModulus(apdubuf, ISO7816.OFFSET_CDATA, MODULUS_LENGTH);
           break;
         }
         case 3: {
           // Try to set random exponent
           m_random.generateData(apdubuf, ISO7816.OFFSET_CDATA, EXPONENT_LENGTH);
           // repair exponent
           apdubuf[ISO7816.OFFSET_CDATA+EXPONENT_LENGTH-1] |= 0x01; // exponent must be odd - set LSB
           apdubuf[ISO7816.OFFSET_CDATA] |= 0x01 << 7; // exponent must be EXPONENT_LENGTH bytes long - set MSB

           // set exponent part of public key
           rsa_PublicKey.setExponent(apdubuf, ISO7816.OFFSET_CDATA, EXPONENT_LENGTH);
           break;
         }
         case 4: {
           // Try to initialize cipher with public key with random exponent
           m_encryptCipherRSA.init(rsa_PublicKey, Cipher.MODE_ENCRYPT);
           break;
         }
         case 5: {
           // Try to encrypt block of data
           short offset = m_encryptCipherRSA.doFinal(apdubuf, (byte) 0, MODULUS_LENGTH, apdubuf, (byte) 0);
           apdu.setOutgoingAndSend((byte) 0, offset);
           break;
         }
       }
   }

void JCSystemInfo(APDU apdu) {
   byte[]    apdubuf = apdu.getBuffer();
   short     dataLen = apdu.setIncomingAndReceive();
   short     offset = (short) 0;

    Util.setShort(apdubuf, offset, JCSystem.getVersion());
    offset = (short)(offset + 2);
    apdubuf[offset] = (JCSystem.isObjectDeletionSupported() ? (byte) 1: (byte) 0);
    offset++;

    Util.setShort(apdubuf, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
    offset = (short)(offset + 2);
    Util.setShort(apdubuf, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
    offset = (short)(offset + 2);
    Util.setShort(apdubuf, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
    offset = (short)(offset + 2);
/**/    
    apdu.setOutgoingAndSend((byte) 0, offset);
  }


  void TestExtendedAPDUSupport(APDU apdu) {
/* ONLY FOR JC2.2.2  
    byte[]    apdubuf = apdu.getBuffer();
    short     LC = apdu.getIncomingLength();
    short     receivedDataTotal = 0;
    short     dataLen = apdu.setIncomingAndReceive();
    short     dataOffset = apdu.getOffsetCdata();
    short     offset = (short) 0;

    // Receive all chunks of data
    while (dataLen > 0) {
        receivedDataTotal += dataLen;
        dataLen = apdu.receiveBytes(dataOffset);
    }

    // Write length indicated by apdu.getIncomingLength()
    Util.setShort(apdubuf, offset, LC);
    offset = (short)(offset + 2);
    
    // Write actual length received
    Util.setShort(apdubuf, offset, receivedDataTotal);
    offset = (short)(offset + 2);

    apdu.setOutgoingAndSend((byte) 0, offset);
*/   }

   void PerformanceTests(APDU apdu) {
       byte[]    apdubuf = apdu.getBuffer();
       short     dataLen = apdu.setIncomingAndReceive();
       short     offset = (short) 0;

       // TODO:

       switch (apdubuf[ISO7816.OFFSET_P1]) {
         case 1: {
           break;
         }
       }
   }

   void TestIOSpeed(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // RETURN INPU DATA UNCHANGED
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }
}

