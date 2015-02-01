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
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

// JC 2.2.2 only
//import javacardx.apdu.ExtendedLength; 
//public class AlgTest extends javacard.framework.Applet implements ExtendedLength 

public class AlgTestSinglePerApdu extends javacard.framework.Applet 
{
    // NOTE: when incrementing version, don't forget to update ALGTEST_JAVACARD_VERSION_CURRENT value

    /**
     * Version 1.3 (30.11.2014)
     * + Possibility to test single algorithm at single apdu command (possibility for reset in between) via TestSupportedModeSingle()
     * - fixed bug with exact specification of Checksum.getInstance(ALG_ISO3309_CRC16... inside TestSupportedModeSingle
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
    final static byte INS_CARD_JCSYSTEM_INFO         = (byte) 0x73;
    final static byte INS_CARD_TESTSUPPORTEDMODES_SINGLE    = (byte) 0x75;

    private   Cipher           m_encryptCipher = null;
    private   Cipher           m_encryptCipherRSA = null;
    private   Signature        m_sign = null;
    private   Key              m_key = null;
    private   MessageDigest    m_digest = null;
    private   RandomData       m_random = null;
    private   Object           m_object = null;
    private   KeyPair          m_keyPair = null;
    
    // for class 'javacard.security.KeyAgreement'
    public static final byte ALG_EC_SVDP_DH = 1;
    
    final static short EXPONENT_LENGTH = (short) 128;
    final static short MODULUS_LENGTH = (short) 128;
    final static short ADDITIONAL_ARGUMENTS_LENGTH = (short) (ISO7816.OFFSET_CDATA + 4); // two short arguments
    
    final static byte SUPP_ALG_UNTOUCHED = (byte) 0xf0;
    final static byte SUPP_ALG_SUPPORTED = (byte) 0x00;
    final static byte SUPP_ALG_EXCEPTION_CODE_OFFSET = (byte) 0;
    

    /**
     * AlgTest default constructor
     * Only this class's install method should create the applet object.
     */
    protected AlgTestSinglePerApdu(byte[] buffer, short offset, byte length)
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
        new AlgTestSinglePerApdu (bArray, bOffset, (byte)bLength );
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
                case INS_CARD_JCSYSTEM_INFO: JCSystemInfo(apdu); break;
                case INS_CARD_TESTSUPPORTEDMODES_SINGLE: TestSupportedModeSingle(apdu); break;

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
    
    void TestSupportedModeSingle(APDU apdu) {
       byte[]    apdubuf = apdu.getBuffer();

       short     dataLen = apdu.setIncomingAndReceive();
       short     offset = -1;
       
       byte      algorithmClass = apdubuf[ISO7816.OFFSET_CDATA];
       short     algorithmParam1 = Util.makeShort(apdubuf[(short) (ISO7816.OFFSET_CDATA + 1)], apdubuf[(short) (ISO7816.OFFSET_CDATA + 2)]);
       //byte ahoj = MessageDigest.ALG_SHA_256;
       
       Util.arrayFillNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, (short) 240, (byte) SUPP_ALG_UNTOUCHED);
       offset++;
       apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = apdubuf[ISO7816.OFFSET_P1];

       switch (apdubuf[ISO7816.OFFSET_P1]) {
           case (byte) 0x11: {
             try {
                 offset++;
                 m_encryptCipher = Cipher.getInstance(algorithmClass, false);
                 apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
             catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
             break;
           }
           case (byte) 0x12: {
             try {offset++;m_sign = Signature.getInstance(algorithmClass, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
             catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
             break;
           }
           case (byte) 0x15: {
             try {offset++;m_digest = MessageDigest.getInstance(algorithmClass, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
             catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
             break;
           }
           case (byte) 0x16: {
             try {offset++;m_random = RandomData.getInstance(algorithmClass); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
             catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
             break;
           }
           case (byte) 0x20: {
             try {offset++;m_key = KeyBuilder.buildKey(algorithmClass, algorithmParam1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
             catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
             break;
           }
           case (byte) 0x19: {
             try {offset++;m_keyPair = new KeyPair(algorithmClass, algorithmParam1); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
             catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
             break;
           }
           
             /*try {
               offset++;m_keyPair = new KeyPair(algorithmClass, algorithmParam1);
               m_keyPair.genKeyPair();
               apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
             }
             catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
             break;*/
           
           case (byte) 0x13: {
             try {offset++;m_object = KeyAgreement.getInstance(ALG_EC_SVDP_DH, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
             catch (CryptoException e) { apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) ? (byte) 0 : (byte) 2;  }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
             break;
           }
           case (byte) 0x17: {
               // error was in Checksum.getInstance(ALG_ISO3309_CRC16, false); - fixed
             try {offset++;m_object = Checksum.getInstance(algorithmClass, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
             catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
             break;
           }
        }
       // ENDING 0xFF
       offset++;
       apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xFF;

       apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 240);
       /**
        * Sends back APDU of length 'offset'
        * APDU of length 240 is too long for no reason
        */
       //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) offset);
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
}