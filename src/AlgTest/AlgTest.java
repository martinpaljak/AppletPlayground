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

public class AlgTest extends javacard.framework.Applet 
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

    byte ALGTEST_JAVACARD_VERSION_CURRENT[] = ALGTEST_JAVACARD_VERSION_1_3;

    
    final static byte CLA_CARD_ALGTEST               = (byte) 0xB0;
    final static byte INS_CARD_GETVERSION            = (byte) 0x60;
    final static byte INS_CARD_TESTSUPPORTEDMODES    = (byte) 0x70;
    final static byte INS_CARD_TESTAVAILABLE_MEMORY  = (byte) 0x71;
    final static byte INS_CARD_TESTRSAEXPONENTSET    = (byte) 0x72;
    final static byte INS_CARD_JCSYSTEM_INFO         = (byte) 0x73;
    final static byte INS_CARD_TESTEXTAPDU           = (byte) 0x74;
    final static byte INS_CARD_TESTSUPPORTEDMODES_SINGLE    = (byte) 0x75;
    final static byte INS_CARD_TESTIOSPEED          = (byte) 0x76;
    final static byte INS_CARD_GETRSAKEY            = (byte) 0x77;


    //
    // CONSTANTS OF ALGORITHMS. USED FOR CARD SUPPORT TEST. TAKEN FROM JavaCard specification
    // Was defined separatelly so we can use single source code even when card do not support
    // particular algorithms and export files do not contain them.
    //
    //
    //Class javacard.security.Signature
    //
    public static final byte ALG_DES_MAC4_NOPAD = 1;
    public static final byte ALG_DES_MAC8_NOPAD = 2;
    public static final byte ALG_DES_MAC4_ISO9797_M1 = 3;
    public static final byte ALG_DES_MAC8_ISO9797_M1 = 4;
    public static final byte ALG_DES_MAC4_ISO9797_M2 = 5;
    public static final byte ALG_DES_MAC8_ISO9797_M2 = 6;
    public static final byte ALG_DES_MAC4_PKCS5 = 7;
    public static final byte ALG_DES_MAC8_PKCS5 = 8;
    public static final byte ALG_RSA_SHA_ISO9796 = 9;
    public static final byte ALG_RSA_SHA_PKCS1 = 10;
    public static final byte ALG_RSA_MD5_PKCS1 = 11;
    public static final byte ALG_RSA_RIPEMD160_ISO9796 = 12;
    public static final byte ALG_RSA_RIPEMD160_PKCS1 = 13;
    public static final byte ALG_DSA_SHA = 14;
    public static final byte ALG_RSA_SHA_RFC2409 = 15;
    public static final byte ALG_RSA_MD5_RFC2409 = 16;
    public static final byte ALG_ECDSA_SHA = 17;
    public static final byte ALG_AES_MAC_128_NOPAD = 18;
    public static final byte ALG_DES_MAC4_ISO9797_1_M2_ALG3 = 19;
    public static final byte ALG_DES_MAC8_ISO9797_1_M2_ALG3 = 20;
    public static final byte ALG_RSA_SHA_PKCS1_PSS = 21;
    public static final byte ALG_RSA_MD5_PKCS1_PSS = 22;
    public static final byte ALG_RSA_RIPEMD160_PKCS1_PSS = 23;
    // JC2.2.2
    public static final byte ALG_HMAC_SHA1 = 24;
    public static final byte ALG_HMAC_SHA_256 = 25;
    public static final byte ALG_HMAC_SHA_384 = 26;
    public static final byte ALG_HMAC_SHA_512 = 27;
    public static final byte ALG_HMAC_MD5 = 28;
    public static final byte ALG_HMAC_RIPEMD160 = 29;
    public static final byte ALG_RSA_SHA_ISO9796_MR = 30;
    public static final byte ALG_RSA_RIPEMD160_ISO9796_MR = 31;
    public static final byte ALG_KOREAN_SEED_MAC_NOPAD = 32;
    // JC3.0.1
    public static final byte ALG_ECDSA_SHA_256 = 33;  
    public static final byte ALG_ECDSA_SHA_384 = 34;  
    public static final byte ALG_AES_MAC_192_NOPAD = 35;  
    public static final byte ALG_AES_MAC_256_NOPAD = 36;  
    public static final byte ALG_ECDSA_SHA_224 = 37;  
    public static final byte ALG_ECDSA_SHA_512 = 38;  
    public static final byte ALG_RSA_SHA_224_PKCS1 = 39;  
    public static final byte ALG_RSA_SHA_256_PKCS1 = 40;  
    public static final byte ALG_RSA_SHA_384_PKCS1 = 41;  
    public static final byte ALG_RSA_SHA_512_PKCS1 = 42;  
    public static final byte ALG_RSA_SHA_224_PKCS1_PSS = 43;  
    public static final byte ALG_RSA_SHA_256_PKCS1_PSS = 44;  
    public static final byte ALG_RSA_SHA_384_PKCS1_PSS = 45;  
    public static final byte ALG_RSA_SHA_512_PKCS1_PSS = 46;  
    // JC3.0.4
    public static final byte ALG_DES_MAC4_ISO9797_1_M1_ALG3 = 47;   
    public static final byte ALG_DES_MAC8_ISO9797_1_M1_ALG3 = 48;
    
    //
    //Class javacardx.crypto.Cipher
    //
    public static final byte ALG_DES_CBC_NOPAD = 1;
    public static final byte ALG_DES_CBC_ISO9797_M1 = 2;
    public static final byte ALG_DES_CBC_ISO9797_M2 = 3;
    public static final byte ALG_DES_CBC_PKCS5 = 4;
    public static final byte ALG_DES_ECB_NOPAD = 5;
    public static final byte ALG_DES_ECB_ISO9797_M1 = 6;
    public static final byte ALG_DES_ECB_ISO9797_M2 = 7;
    public static final byte ALG_DES_ECB_PKCS5 = 8;
    public static final byte ALG_RSA_ISO14888 = 9;
    public static final byte ALG_RSA_PKCS1 = 10;
    public static final byte ALG_RSA_ISO9796 = 11;
    public static final byte ALG_RSA_NOPAD = 12;
    public static final byte ALG_AES_BLOCK_128_CBC_NOPAD = 13;
    public static final byte ALG_AES_BLOCK_128_ECB_NOPAD = 14;
    public static final byte ALG_RSA_PKCS1_OAEP = 15;
    // JC2.2.2
    public static final byte ALG_KOREAN_SEED_ECB_NOPAD = 16;
    public static final byte ALG_KOREAN_SEED_CBC_NOPAD = 17;
    // JC3.0.1
    public static final byte ALG_AES_BLOCK_192_CBC_NOPAD = 18;  
    public static final byte ALG_AES_BLOCK_192_ECB_NOPAD = 19;  
    public static final byte ALG_AES_BLOCK_256_CBC_NOPAD = 20;  
    public static final byte ALG_AES_BLOCK_256_ECB_NOPAD = 21;  
    public static final byte ALG_AES_CBC_ISO9797_M1 = 22;  
    public static final byte ALG_AES_CBC_ISO9797_M2 = 23;  
    public static final byte ALG_AES_CBC_PKCS5 = 24;  
    public static final byte ALG_AES_ECB_ISO9797_M1 = 25;  
    public static final byte ALG_AES_ECB_ISO9797_M2 = 26;  
    public static final byte ALG_AES_ECB_PKCS5 = 27;      


    //
    //Class javacard.security.KeyAgreement
    //
    public static final byte ALG_EC_SVDP_DH = 1;
    public static final byte ALG_EC_SVDP_DHC = 2;
    // JC3.0.1
    public static final byte ALG_EC_SVDP_DH_KDF = 1;  
    public static final byte ALG_EC_SVDP_DH_PLAIN = 3;     
    public static final byte ALG_EC_SVDP_DHC_KDF = 2;  
    public static final byte ALG_EC_SVDP_DHC_PLAIN = 4;  
    
    //
    //Class javacard.security.KeyBuilder
    //
    public static final byte TYPE_DES_TRANSIENT_RESET = 1;
    public static final byte TYPE_DES_TRANSIENT_DESELECT = 2;
    public static final byte TYPE_DES = 3;
    public static final byte TYPE_RSA_PUBLIC = 4;
    public static final byte TYPE_RSA_PRIVATE = 5;
    public static final byte TYPE_RSA_CRT_PRIVATE = 6;
    public static final byte TYPE_DSA_PUBLIC = 7;
    public static final byte TYPE_DSA_PRIVATE = 8;
    public static final byte TYPE_EC_F2M_PUBLIC = 9;
    public static final byte TYPE_EC_F2M_PRIVATE = 10;
    public static final byte TYPE_EC_FP_PUBLIC = 11;
    public static final byte TYPE_EC_FP_PRIVATE = 12;
    public static final byte TYPE_AES_TRANSIENT_RESET = 13;
    public static final byte TYPE_AES_TRANSIENT_DESELECT = 14;
    public static final byte TYPE_AES = 15;
    // JC2.2.2
    public static final byte TYPE_KOREAN_SEED_TRANSIENT_RESET = 16;
    public static final byte TYPE_KOREAN_SEED_TRANSIENT_DESELECT = 17;
    public static final byte TYPE_KOREAN_SEED = 18;
    public static final byte TYPE_HMAC_TRANSIENT_RESET = 19;
    public static final byte TYPE_HMAC_TRANSIENT_DESELECT = 20;
    public static final byte TYPE_HMAC = 21;
    // JC3.0.1
    public static final byte TYPE_RSA_PRIVATE_TRANSIENT_RESET = 22;  
    public static final byte TYPE_RSA_PRIVATE_TRANSIENT_DESELECT = 23;  
    public static final byte TYPE_RSA_CRT_PRIVATE_TRANSIENT_RESET = 24;  
    public static final byte TYPE_RSA_CRT_PRIVATE_TRANSIENT_DESELECT = 25;  
    public static final byte TYPE_DSA_PRIVATE_TRANSIENT_RESET = 26;
    public static final byte TYPE_DSA_PRIVATE_TRANSIENT_DESELECT = 27;  
    public static final byte TYPE_EC_F2M_PRIVATE_TRANSIENT_RESET = 28;  
    public static final byte TYPE_EC_F2M_PRIVATE_TRANSIENT_DESELECT = 29;  
    public static final byte TYPE_EC_FP_PRIVATE_TRANSIENT_RESET = 30;  
    public static final byte TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT = 31;  

    
    public static final short LENGTH_DES = 64;
    public static final short LENGTH_DES3_2KEY = 128;
    public static final short LENGTH_DES3_3KEY = 192;
    public static final short LENGTH_RSA_512 = 512;
    public static final short LENGTH_RSA_736 = 736;
    public static final short LENGTH_RSA_768 = 768;
    public static final short LENGTH_RSA_896 = 896;
    public static final short LENGTH_RSA_1024 = 1024;
    public static final short LENGTH_RSA_1280 = 1280;
    public static final short LENGTH_RSA_1536 = 1536;
    public static final short LENGTH_RSA_1984 = 1984;
    public static final short LENGTH_RSA_2048 = 2048;
    public static final short LENGTH_DSA_512 = 512;
    public static final short LENGTH_DSA_768 = 768;
    public static final short LENGTH_DSA_1024 = 1024;
    public static final short LENGTH_EC_FP_112 = 112;
    public static final short LENGTH_EC_F2M_113 = 113;
    public static final short LENGTH_EC_FP_128 = 128;
    public static final short LENGTH_EC_F2M_131 = 131;
    public static final short LENGTH_EC_FP_160 = 160;
    public static final short LENGTH_EC_F2M_163 = 163;
    public static final short LENGTH_EC_FP_192 = 192;
    public static final short LENGTH_EC_F2M_193 = 193;
    public static final short LENGTH_AES_128 = 128;
    public static final short LENGTH_AES_192 = 192;
    public static final short LENGTH_AES_256 = 256;
    // JC2.2.2
    public static final short LENGTH_KOREAN_SEED_128= 128;
    public static final short LENGTH_HMAC_SHA_1_BLOCK_64= 64;
    public static final short LENGTH_HMAC_SHA_256_BLOCK_64= 64;
    public static final short LENGTH_HMAC_SHA_384_BLOCK_64= 128;
    public static final short LENGTH_HMAC_SHA_512_BLOCK_64= 128;
    // JC3.0.1
    public static final short LENGTH_EC_FP_224 = 224;  
    public static final short LENGTH_EC_FP_256 = 256;  
    public static final short LENGTH_EC_FP_384 = 384;  
    public static final short LENGTH_RSA_3072 = 3072;
    public static final short LENGTH_RSA_4096 = 4096;
    //JC3.0.4
    public static final short LENGTH_EC_FP_521 = 521;
    
    //
    //Class javacard.security.KeyPair
    //
    public static final byte ALG_RSA = 1;
    public static final byte ALG_RSA_CRT = 2;
    public static final byte ALG_DSA = 3;
    public static final byte ALG_EC_F2M = 4;
    public static final byte ALG_EC_FP = 5;

    //Class javacard.security.MessageDigest
    public static final byte ALG_SHA = 1;
    public static final byte ALG_MD5 = 2;
    public static final byte ALG_RIPEMD160 = 3;
    // JC2.2.2
    public static final byte ALG_SHA_256 = 4;
    public static final byte ALG_SHA_384 = 5;
    public static final byte ALG_SHA_512 = 6;
    // JC3.0.1
    public static final byte ALG_SHA_224 = 7;
    
    // JC2.2.2
    public static final byte LENGTH_MD5 = 16; 
    public static final byte LENGTH_RIPEMD160 = 20;  
    public static final byte LENGTH_SHA = 20;  
    public static final byte LENGTH_SHA_256 = 32;  
    public static final byte LENGTH_SHA_384 = 48;  
    public static final byte LENGTH_SHA_512 = 64;  
    // JC3.0.4
    public static final byte LENGTH_SHA_224 = 28;  

    //Class javacard.security.RandomData
    public static final byte ALG_PSEUDO_RANDOM = 1;
    public static final byte ALG_SECURE_RANDOM = 2;

    // Class javacard.security.Checksum
    public static final byte ALG_ISO3309_CRC16 = 1;
    public static final byte ALG_ISO3309_CRC32 = 2;



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
    private   RSAPrivateCrtKey rsa_PrivateKey = null;

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
    protected AlgTest(byte[] buffer, short offset, byte length)
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
        new AlgTest (bArray, bOffset, (byte)bLength );
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
                case INS_CARD_TESTSUPPORTEDMODES: TestSupportedModes(apdu); break;
                case INS_CARD_TESTAVAILABLE_MEMORY: TestAvailableMemory(apdu); break;
                case INS_CARD_TESTRSAEXPONENTSET: TestRSAExponentSet(apdu); break;
                case INS_CARD_JCSYSTEM_INFO: JCSystemInfo(apdu); break;
                case INS_CARD_TESTEXTAPDU: TestExtendedAPDUSupport(apdu); break;
                case INS_CARD_TESTSUPPORTEDMODES_SINGLE: TestSupportedModeSingle(apdu); break;
                case INS_CARD_TESTIOSPEED: TestIOSpeed(apdu); break;
                case INS_CARD_GETRSAKEY: GetRSAKey(apdu); break;

                default : {
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
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

       Util.arrayFillNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, (short) 240, (byte) SUPP_ALG_UNTOUCHED);
       offset++;
       apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = apdubuf[ISO7816.OFFSET_P1];

       switch (apdubuf[ISO7816.OFFSET_P1]) {
           case (byte) 0x11: {
             try {offset++;m_encryptCipher = Cipher.getInstance(algorithmClass, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
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
           case (byte) 0x18: // no break
           case (byte) 0x19: // no break
           case (byte) 0x1C: { // no break
             try {
               offset++;m_keyPair = new KeyPair(algorithmClass, algorithmParam1);
               m_keyPair.genKeyPair();
               apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
             }
             catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
             break;
           }
           case (byte) 0x13: {
             try {offset++;m_object = KeyAgreement.getInstance(ALG_EC_SVDP_DH, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
             catch (CryptoException e) { apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) ? (byte) 0 : (byte) 2;  }
             // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
               break;
           }
           case (byte) 0x17: {
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
        * TODO: Sends back APDU of length 'offset'
        * APDU of length 240 is too long for no reason
        */
       //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) offset);
    }
    
    void TestSupportedModes(APDU apdu) {
       byte[]    apdubuf = apdu.getBuffer();

       short     dataLen = apdu.setIncomingAndReceive();
       short     offset = -1;

       Util.arrayFillNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, (short) 240, (byte) SUPP_ALG_UNTOUCHED);

       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x11) {
         // Class javacardx.crypto.Cipher
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x11;

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_DES_CBC_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_DES_CBC_ISO9797_M1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_DES_CBC_ISO9797_M2, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_DES_CBC_PKCS5, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_DES_ECB_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_DES_ECB_ISO9797_M1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_DES_ECB_ISO9797_M2, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_DES_ECB_PKCS5, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_RSA_ISO14888, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_RSA_PKCS1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_RSA_ISO9796, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_RSA_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_BLOCK_128_CBC_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_BLOCK_128_ECB_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_RSA_PKCS1_OAEP, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        // JC2.2.2
        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_KOREAN_SEED_ECB_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_KOREAN_SEED_CBC_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        // JC3.0.1
        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_BLOCK_192_CBC_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_BLOCK_192_ECB_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_BLOCK_256_CBC_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_BLOCK_256_ECB_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_CBC_ISO9797_M1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_CBC_ISO9797_M2, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_CBC_PKCS5, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_ECB_ISO9797_M1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_ECB_ISO9797_M2, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_encryptCipher = Cipher.getInstance(ALG_AES_ECB_PKCS5, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
       }

       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x12) {
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x12;
        //Class javacard.security.Signature
        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC4_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC8_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC4_ISO9797_M1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC8_ISO9797_M1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC4_ISO9797_M2, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC8_ISO9797_M2, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC4_PKCS5, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC8_PKCS5, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_ISO9796, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_PKCS1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_MD5_PKCS1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_RIPEMD160_ISO9796, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_RIPEMD160_PKCS1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DSA_SHA, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_RFC2409, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_MD5_RFC2409, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_ECDSA_SHA, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_AES_MAC_128_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC4_ISO9797_1_M2_ALG3, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC8_ISO9797_1_M2_ALG3, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_PKCS1_PSS, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_MD5_PKCS1_PSS, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_RIPEMD160_PKCS1_PSS, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        // JC2.2.2
        try {offset++;m_sign = Signature.getInstance(ALG_HMAC_SHA1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_HMAC_SHA_256, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_HMAC_SHA_384, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_HMAC_SHA_512, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_HMAC_MD5, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_HMAC_RIPEMD160, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_ISO9796_MR, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_RIPEMD160_ISO9796_MR, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_KOREAN_SEED_MAC_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        // JC3.0.1
        try {offset++;m_sign = Signature.getInstance(ALG_ECDSA_SHA_256, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_ECDSA_SHA_384, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_AES_MAC_192_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_AES_MAC_256_NOPAD, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_ECDSA_SHA_224, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_ECDSA_SHA_512, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_224_PKCS1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_256_PKCS1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_384_PKCS1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_512_PKCS1, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_224_PKCS1_PSS, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_256_PKCS1_PSS, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_384_PKCS1_PSS, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_RSA_SHA_512_PKCS1_PSS, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC4_ISO9797_1_M1_ALG3, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_sign = Signature.getInstance(ALG_DES_MAC8_ISO9797_1_M1_ALG3, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
       }

       //       Class javacard.security.MessageDigest
       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x15) {
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x15;
        try {offset++;m_digest = MessageDigest.getInstance(ALG_SHA, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_digest = MessageDigest.getInstance(ALG_MD5, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_digest = MessageDigest.getInstance(ALG_RIPEMD160, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        //JC2.2.2
        try {offset++;m_digest = MessageDigest.getInstance(ALG_SHA_256, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_digest = MessageDigest.getInstance(ALG_SHA_384, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_digest = MessageDigest.getInstance(ALG_SHA_512, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        //JC3.0.1
        try {offset++;m_digest = MessageDigest.getInstance(ALG_SHA_224, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
       }

       //       Class javacard.security.RandomData
       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x16) {
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x16;

         try {offset++;m_random = RandomData.getInstance(ALG_PSEUDO_RANDOM); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
         catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
         // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

         try {offset++;m_random = RandomData.getInstance(ALG_SECURE_RANDOM); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
         catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
         // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
       }
/**/
       //       Class javacard.security.KeyBuilder
       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x20) {

         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x20;

        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xB0;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DES_TRANSIENT_RESET, LENGTH_DES, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DES_TRANSIENT_DESELECT, LENGTH_DES, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DES, LENGTH_DES, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DES, LENGTH_DES3_2KEY, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DES, LENGTH_DES3_3KEY, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}


        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xB1;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_AES_TRANSIENT_RESET, LENGTH_AES_128, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_AES_TRANSIENT_DESELECT, LENGTH_AES_128, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_AES, LENGTH_AES_128, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_AES, LENGTH_AES_192, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_AES, LENGTH_AES_256, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

/**/

        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xB2;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_512, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_736, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_768, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_896, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_1280, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_1536, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_1984, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_2048, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_3072, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PUBLIC, LENGTH_RSA_4096, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

/**/

        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xB3;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_512, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_736, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_768, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_896, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_1280, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_1536, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_1984, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_2048, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_3072, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE, LENGTH_RSA_4096, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        // JC3.0.1         
        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE_TRANSIENT_RESET, LENGTH_RSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_PRIVATE_TRANSIENT_DESELECT, LENGTH_RSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}


        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xB4;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_512, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_736, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_768, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_896, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_1280, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_1536, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_1984, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_2048, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_3072, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE, LENGTH_RSA_4096, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        // JC3.0.1         
        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE_TRANSIENT_RESET, LENGTH_RSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_RSA_CRT_PRIVATE_TRANSIENT_DESELECT, LENGTH_RSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}         
/**/

        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xB5;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DSA_PRIVATE, LENGTH_DSA_512, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DSA_PRIVATE, LENGTH_DSA_768, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DSA_PRIVATE, LENGTH_DSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        // JC3.0.1
        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DSA_PRIVATE_TRANSIENT_RESET, LENGTH_DSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DSA_PRIVATE_TRANSIENT_DESELECT, LENGTH_DSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}


        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xB6;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DSA_PUBLIC, LENGTH_DSA_512, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DSA_PUBLIC, LENGTH_DSA_768, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_DSA_PUBLIC, LENGTH_DSA_1024, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}


        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xB7;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_EC_F2M_113, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_EC_F2M_131, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_EC_F2M_163, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_EC_F2M_193, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        // JC3.0.1
        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE_TRANSIENT_RESET, LENGTH_EC_F2M_193, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE_TRANSIENT_DESELECT, LENGTH_EC_F2M_193, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}


        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xB8;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_112, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_128, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_160, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_192, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        // JC3.0.1
        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_224, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_384, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}         

        // JC3.0.4
        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_521, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}              

        // JC3.0.1
        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, LENGTH_EC_FP_128, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, LENGTH_EC_FP_128, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}         

        //JC2.2.2
        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xB9;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_KOREAN_SEED_TRANSIENT_RESET, LENGTH_KOREAN_SEED_128, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_KOREAN_SEED_TRANSIENT_DESELECT, LENGTH_KOREAN_SEED_128, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_KOREAN_SEED, LENGTH_KOREAN_SEED_128, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}


        offset++;
        apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xBA;

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_HMAC_TRANSIENT_RESET, LENGTH_HMAC_SHA_1_BLOCK_64, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_HMAC_TRANSIENT_DESELECT, LENGTH_HMAC_SHA_1_BLOCK_64, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_HMAC, LENGTH_HMAC_SHA_1_BLOCK_64, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_HMAC, LENGTH_HMAC_SHA_256_BLOCK_64, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_HMAC, LENGTH_HMAC_SHA_384_BLOCK_64, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        try {offset++;m_key = KeyBuilder.buildKey(TYPE_HMAC, LENGTH_HMAC_SHA_512_BLOCK_64, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
        catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
        // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
       }


       //       Class javacard.security.KeyPair RSA
       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x18) {
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x18;

        // TEST ON-CARD KEY GENERATION
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x01) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_512);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

        }
        else { offset++; }
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x02) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_736);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x03) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_768);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x04) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_896);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x05) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_1024);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x06) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_1280);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x07) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_1536);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x08) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_1984);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x09) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_2048);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x0A) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_3072);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x0B) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA, LENGTH_RSA_4096);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
       }

       //       Class javacard.security.KeyPair RSA_CRT
       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x19) {
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x19;

         // TEST ON-CARD KEY GENERATION
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x01) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_512);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x02) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_736);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x03) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_768);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x04) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_896);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x05) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_1024);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x06) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_1280);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x07) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_1536);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x08) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_1984);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x09) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_2048);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x0A) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_3072);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }

        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x0B) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_4096);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
       }

       //       Class javacard.security.KeyPair DSA
       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x1A) {
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x1A;

         // TEST ON-CARD KEY GENERATION
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x01) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_DSA, LENGTH_DSA_512);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x02) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_DSA, LENGTH_DSA_768);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
        if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x03) {
          try {
            offset++;m_keyPair = new KeyPair(ALG_DSA, LENGTH_DSA_1024);
            m_keyPair.genKeyPair();
            apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
          }
          catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
          // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
        }
        else { offset++; }
       }
       //       Class javacard.security.KeyPair EC_F2M
       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x1B) {
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x1B;

         // TEST ON-CARD KEY GENERATION
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x01) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_F2M, LENGTH_EC_F2M_113);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x02) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_F2M, LENGTH_EC_F2M_131);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x03) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_F2M, LENGTH_EC_F2M_163);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x04) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_F2M, LENGTH_EC_F2M_193);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
       }

       //       Class javacard.security.KeyPair EC_FP
       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x1C) {
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x1C;

         // TEST ON-CARD KEY GENERATION
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x01) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_FP, LENGTH_EC_FP_112);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x02) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_FP, LENGTH_EC_FP_128);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x03) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_FP, LENGTH_EC_FP_160);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x04) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_FP, LENGTH_EC_FP_192);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x04) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_FP, LENGTH_EC_FP_224);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x04) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_FP, LENGTH_EC_FP_256);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x04) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_FP, LENGTH_EC_FP_384);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
         if (apdubuf[ISO7816.OFFSET_P2] == 0 || apdubuf[ISO7816.OFFSET_P2] == (byte) 0x04) {
           try {
             offset++;m_keyPair = new KeyPair(ALG_EC_FP, LENGTH_EC_FP_521);
             m_keyPair.genKeyPair();
             apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;
           }
           catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
           // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         }
         else { offset++; }
       }
/**/

       //       Class javacard.security.KeyAgreement
       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x13) {
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x13;

         try {offset++;m_object = KeyAgreement.getInstance(ALG_EC_SVDP_DH, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
         catch (CryptoException e) { apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) ? (byte) 0 : (byte) 2;  }
         // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

         try {offset++;m_object = KeyAgreement.getInstance(ALG_EC_SVDP_DHC, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
         catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
         // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

         // JC3.0.1
         try {offset++;m_object = KeyAgreement.getInstance(ALG_EC_SVDP_DH_KDF, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
         catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
         // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

         try {offset++;m_object = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
         catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
         // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

         try {offset++;m_object = KeyAgreement.getInstance(ALG_EC_SVDP_DHC_KDF, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
         catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
         // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}

         try {offset++;m_object = KeyAgreement.getInstance(ALG_EC_SVDP_DHC_PLAIN, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
         catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
         // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
       }

       //       Class javacard.security.Checksum
       if (apdubuf[ISO7816.OFFSET_P1] == 0 || apdubuf[ISO7816.OFFSET_P1] == (byte) 0x17) {
         offset++;
         apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0x17;
         try {offset++;m_object = Checksum.getInstance(ALG_ISO3309_CRC16, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
         catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
         // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
         
         try {offset++;m_object = Checksum.getInstance(ALG_ISO3309_CRC32, false); apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = SUPP_ALG_SUPPORTED;}
         catch (CryptoException e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) (e.getReason() + SUPP_ALG_EXCEPTION_CODE_OFFSET); }
         // catch (Exception e) {apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte)0x6f;}
       }
/**/
       // ENDING 0xFF
       offset++;
       apdubuf[(short) (ISO7816.OFFSET_CDATA + offset)] = (byte) 0xFF;

       apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 240);
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
   
    void GetRSAKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      //apdu.setIncomingAndReceive();

      // Generate new object if not before yet
      if (m_keyPair == null) {
          m_keyPair = new KeyPair(ALG_RSA_CRT, LENGTH_RSA_1024);	  
      }	        

      switch (apdubuf[ISO7816.OFFSET_P1]) {
        case 0: {
            m_keyPair.genKeyPair();           
            rsa_PublicKey = (RSAPublicKey) m_keyPair.getPublic();

            /*            
            short offset = rsa_PublicKey.getExponent(apdubuf, (short) 0);
            offset += rsa_PublicKey.getModulus(apdubuf, offset);
            */
            
            short offset = 0;
            apdubuf[offset] = (byte)0x82; offset++;
            short len = rsa_PublicKey.getExponent(apdubuf, (short)(offset + 2));
            Util.setShort(apdubuf, offset, len); 
            offset += 2;    // length
            offset += len;  // value
            
            apdubuf[offset] = (byte)0x82; offset++;
            len = rsa_PublicKey.getModulus(apdubuf, (short) (offset + 2));
            Util.setShort(apdubuf, offset, len); 
            offset += 2;    // length
            offset += len;  // value

            apdu.setOutgoingAndSend((short) 0, offset);
        
            break;
        }
        case 1: {
            rsa_PrivateKey = (RSAPrivateCrtKey) m_keyPair.getPrivate();
            
            short offset = 0;
            short len = rsa_PrivateKey.getP(apdubuf, (short)(offset + 3));
            apdubuf[offset] = (byte)0x82; offset++;
            Util.setShort(apdubuf, offset, len); offset += 2;
            offset += len;
            
            len = rsa_PrivateKey.getQ(apdubuf, (short)(offset + 3));
            apdubuf[offset] = (byte)0x82; offset++;
            Util.setShort(apdubuf, offset, len); offset += 2;
            offset += len;
                    
            apdu.setOutgoingAndSend((short) 0, offset);
            break;
         }
      }
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

