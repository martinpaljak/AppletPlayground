//  MUSCLE SmartCard Development
//      Authors: Tommaso Cucinotta <cucinotta@sssup.it>
//	         David Corcoran    <corcoran@linuxnet.com>
//	         Ludovic Rousseau  <ludovic.rousseau@free.fr>
//	         Jamie Nicolson    <nicolson@netscape.com>
//	         Robert Relyea     <rrelyea@redhat.com>
//	         Nelson Bolyard    <nelsonb@netscape.com>
//      Package:         CardEdgeApplet
//      Description:      CardEdge implementation with JavaCard
//      Protocol Authors: Tommaso Cucinotta <cucinotta@sssup.it>
//	                  David Corcoran <corcoran@linuxnet.com>
//      Modified:
//	                  Eirik Herskedal <ehersked@cs.purdue.edu>
//
// BEGIN LICENSE BLOCK
// Copyright (C) 1999-2002 David Corcoran <corcoran@linuxnet.com>
// Copyright (C) 2006 Red Hat, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// Changes to this license can be made only by the copyright author with
// explicit written consent.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Alternatively, the contents of this file may be used under the terms of
// the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
// case the provisions of the LGPL are applicable instead of those above. If
// you wish to allow use of your version of this file only under the terms
// of the LGPL, and not to allow others to use your version of this file
// under the terms of the BSD license, indicate your decision by deleting
// the provisions above and replace them with the notice and other
// provisions required by the LGPL. If you do not delete the provisions
// above, a recipient may use your version of this file under the terms of
// either the BSD license or the LGPL.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
// END LICENSE_BLOCK

package com.redhat.ckey.applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

import visa.openplatform.ProviderSecurityDomain;
import visa.openplatform.OPSystem;

// Referenced classes of package com.redhat.ckey.applet:
//	    MemoryManager, ObjectManager, ASN1

/**
 * Implements MUSCLE's Card Edge Specification.
 * 
 * <p>TODO:
 * 
 * <ul>
 *  <li>Allows maximum number of keys and PINs and total mem to be specified at the instantiation moment.</li>
 * 
 *  <li>How do transactions fit in the methods?</li>
 *  <li>Where should we issue begin/end transaction?</li>
 *  <li>Should we ever abort transaction? Where?</li>
 *  <li>Everytime there is an <tt>"if (avail &lt; )"</tt> check, call <tt>ThrowDeleteObjects()</tt>.</li>
 * </ul>
 * </p>
 * 
 * <p>NOTES:
 * 
 * <ul>
 *  <li>C preprocessor flags:
 *   <ul>
 *    <li>Encryption algorithms: WITH_RSA, WITH_DSA, WITH_DES, WITH_3DES</li>
 *    <li>ComputeCrypt directions: WITH_ENCRYPT, WITH_DECRYPT, WITH_SIGN</li>
 *    <li>Enable/Disable External Authenticate: WITH_EXT_AUTH</li>
 *    <li>Enable/Disable PIN Policy enforcement: WITH_PIN_POLICY</li>
 *   </ul>
*  </li>
 *  <li>C preprocessor defines:
 *   <ul>
 *    <li>JAVA_PACKAGE: The name of Java package for this Applet</li>
 *    <li>CardEdge: The name of Java class for the Applet</li>
 *   </ul>
 *  </li>
 * </ul>
 * </p>
 *
 * @author Tommaso Cucinotta
 * @author David Corcoran
 * @author Ludovic Rousseau
 * @version 0.9.10
 */


public class CardEdge extends Applet
{
    private static final byte ZEROB = 0;
    private static final byte MAX_NUM_KEYS = 24;
    private static final byte MAX_NUM_PINS = 8;
    
    private static final byte VERSION_PROTOCOL_MAJOR = 1;
    private static final byte VERSION_PROTOCOL_MINOR = 1;
    private static final byte VERSION_APPLET_MAJOR = 1;
    private static final byte VERSION_APPLET_MINOR = 4;
    private static final short BUILDID_MAJOR = (short) 0x5261;
    private static final short BUILDID_MINOR = (short) 0x7c4e;
    private static final short ZEROS = 0;

    // * Enable pin size check
    private static final byte PIN_POLICY_SIZE = 1;

    // * Enable pin charset check
    private static final byte PIN_POLICY_CHARSET = 2;

    // * Enable charset mixing check
    private static final byte PIN_POLICY_MIXED = 4;

    // * Numbers are allowed
    private static final byte PIN_CHARSET_NUMBERS = 1;

    // * Upper case letters
    private static final byte PIN_CHARSET_UC_LETTERS = 2;

    // * Lower case letters
    private static final byte PIN_CHARSET_LC_LETTERS = 4;

    // * Punctuation symbols: , .
    private static final byte PIN_CHARSET_PUNCT = 8;

    // * Other binary codes (NUMBERS | OTHERS excludes LETTERS and PUNCT)
    private static final byte PIN_CHARSET_OTHERS = (byte)0x80;

    // * PIN must contain chars from at least 2 different char sets
    private static final byte PIN_MIXED_TWO = 1;

    // * PIN must at least contain chars from both upper and lower case
    private static final byte PIN_MIXED_CASE = 2;

    // * PIN must at least contain 1 char from each char set
    private static final byte PIN_MIXED_ALL = 4;

    /**
     * The User's PIN is pin 0. There is no SO pin.
     */
    private static final byte  USER_IDENTITY    = 0;
    private static final byte  DEFAULT_IDENTITY = 15; // MUSCLE reserved ID
    private static final byte  RA_IDENTITY      = 14; // MUSCLE reserved ID
    private static final short NONCE_SIZE       = (short)8;
    private static final short ISSUER_INFO_SIZE = (short)0xe0;

    private static final short USER_ACL       = (short)(1 << USER_IDENTITY); 
    private static final short DEFAULT_ACL    = (short)(1 << DEFAULT_IDENTITY); 
    private static final short RA_ACL         = (short)(1 << RA_IDENTITY);
    private static final short ANY_ONE_ACL    = (short)0xffff;
    private static final short NO_ONE_ACL     = (short)0;
    
    private static final byte pinPolicies     = 7;
    private static final byte pinMinSize      = 4;
    private static final byte pinMaxSize      = 16;
    
    private static final byte MAX_KEY_TRIES   = 5;
    private static final short IN_OBJECT_CLA  = -1;
    private static final short IN_OBJECT_ID   = -2;
    private static final short OUT_OBJECT_CLA = -1;
    private static final short OUT_OBJECT_ID  = -1;
    private static final byte KEY_ACL_SIZE    = 6;
    
    private static final byte CardEdge_CLA    = (byte)0xB0;
    private static final byte CardManager_CLA = (byte)0x80;
    private static final byte SECURE_CLA      = (byte)0x84;

    /**
     * Instruction codes
     */
    /* Deprecated */
    private static final byte INS_SETUP         = (byte)0x2A;
    private static final byte INS_GEN_KEYPAIR   = (byte)0x30;
    private static final byte INS_EXPORT_KEY    = (byte)0x34;
    private static final byte INS_UNBLOCK_PIN   = (byte)0x46;
    private static final byte INS_GET_CHALLENGE = (byte)0x62;
    private static final byte INS_CAC_EXT_AUTH  = (byte)0x38;
    private static final byte INS_LOGOUT_ALL    = (byte)0x60;

    /* public */
    private static final byte INS_VERIFY_PIN      = (byte)0x42;
    private static final byte INS_LIST_OBJECTS    = (byte)0x58;
    private static final byte INS_LIST_PINS       = (byte)0x48;
    private static final byte INS_LIST_KEYS       = (byte)0x3A;
    private static final byte INS_GET_STATUS      = (byte)0x3C;
    private static final byte INS_GET_LIFECYCLE   = (byte)0xF2;
    private static final byte INS_GET_ISSUER_INFO = (byte)0xF6;
    private static final byte INS_GET_BUILDID     = (byte)0x70;
    private static final byte INS_NOP             = (byte)0x71;
    private static final byte INS_GET_RANDOM      = (byte)0x72;
    private static final byte INS_SEED_RANDOM     = (byte)0x73;
    private static final byte INS_GET_BUILTIN_ACL = (byte)0xFA;

    /* nonce validated only */
    private static final byte INS_LOGOUT	= (byte)0x61;

    /* nonce validated  & Secure Channel */
    private static final byte INS_IMPORT_KEY    = (byte)0x32;
    private static final byte INS_COMPUTE_CRYPT = (byte)0x36;
    private static final byte INS_CREATE_PIN    = (byte)0x40;
    private static final byte INS_CHANGE_PIN    = (byte)0x44;
    private static final byte INS_CREATE_OBJ    = (byte)0x5A;
    private static final byte INS_DELETE_OBJ    = (byte)0x52;
    private static final byte INS_READ_OBJ      = (byte)0x56;
    private static final byte INS_WRITE_OBJ     = (byte)0x54;

    
    /* Secure channel only */
    private static final byte INS_INIT_UPDATE               = (byte)0x50;
    private static final byte INS_SEC_EXT_AUTH              = (byte)0x82;
    private static final byte INS_SEC_SET_LIFECYCLE         = (byte)0xF0;
    private static final byte INS_SEC_SET_ISSUER_INFO       = (byte)0xF4;
    private static final byte INS_SEC_SET_BUILTIN_ACL       = (byte)0xF8;
    private static final byte INS_SEC_SET_PIN               = (byte)0x04;
    private static final byte INS_SEC_READ_IOBUF            = (byte)0x08;
    private static final byte INS_SEC_IMPORT_KEY_ENCRYPTED  = (byte)0x0A;
    private static final byte INS_SEC_START_ENROLLMENT      = (byte)0x0C;


    // * There have been memory problems on the card
    private static final short SW_NO_MEMORY_LEFT	= (short)0x9C01;

    // * Entered PIN is not correct
    private static final short SW_AUTH_FAILED	   = (short)0x9C02;

    // * Required operation is not allowed in actual circumstances
    private static final short SW_OPERATION_NOT_ALLOWED = (short)0x9C03;

    // * Required feature is not (yet) supported
    private static final short SW_UNSUPPORTED_FEATURE   = (short)0x9C05;

    // * Required operation was not authorized because of a lack of privileges
    private static final short SW_UNAUTHORIZED	  = (short)0x9C06;

    // * Required object is missing
    private static final short SW_OBJECT_NOT_FOUND      = (short)0x9C07;

    // * New object ID already in use
    private static final short SW_OBJECT_EXISTS	 = (short)0x9C08;

    // * Algorithm specified is not correct
    private static final short SW_INCORRECT_ALG	 = (short)0x9C09;

    // * Verify operation detected an invalid signature
    private static final short SW_SIGNATURE_INVALID     = (short)0x9C0B;

    // * Operation has been blocked for security reason
    private static final short SW_IDENTITY_BLOCKED      = (short)0x9C0C;

    //  * Unspecified Applet error
    private static final short SW_UNSPECIFIED_ERROR     = (short)0x9C0D;

    // * Invalid input parameter to command
    private static final short SW_INVALID_PARAMETER     = (short)0x9C0F;

    // * Incorrect P1 parameter
    private static final short SW_INCORRECT_P1	  = (short)0x9C10;

    // * Incorrect P2 parameter
    private static final short SW_INCORRECT_P2	  = (short)0x9C11;

    // * No more data available
    private static final short SW_SEQUENCE_END	  = (short)0x9C12;

    // * Cipher Direction given is not supported for this Operation
    private static final short SW_DIRECTION_UNSUPPORTED = (short)0x9C13;

    // * Cipher Direction invalid, unrecognized
    private static final short SW_DIRECTION_INVALID     = (short)0x9C14;

    // * Data Location given is not supported for this Operation
    private static final short SW_LOCATION_UNSUPPORTED  = (short)0x9C15;

    // * Data Location invalid, unrecognized
    private static final short SW_LOCATION_INVALID      = (short)0x9C16;

    // * Key Type given is not supported for this Operation and Direction
    private static final short SW_KEY_TYPE_UNSUPPORTED  = (short)0x9C17;

    // * Key Type invalid, unrecognized
    private static final short SW_KEY_TYPE_INVALID      = (short)0x9C18;

    // * Data Chunk Size Invalid
    private static final short SW_DATA_CHUNK_SIZE_ERROR = (short)0x9C19;

    // * Key Size Invalid
    private static final short SW_KEY_SIZE_ERROR	= (short)0x9C1A;

    // * Cipher Mode given is not supported for this Operation and Direction
    private static final short SW_CIPH_MODE_UNSUPPORTED = (short)0x9C1B;

    // * Cipher Mode invalid, unrecognized
    private static final short SW_CIPH_MODE_INVALID     = (short)0x9C1C;

    // * Output space insufficient to hold result.
    private static final short SW_OUT_BUF_TOO_SMALL     = (short)0x9C1D;

    // * Key slots already assigned with different pairing
    private static final short SW_INCONSTANT_KEYPAIRING = (short)0x9C1E;

    // * Input space insufficient to decode result.
    private static final short SW_IN_BUF_TOO_SMALL     = (short)0x9C1F;

    // * Wrapped Key failed verify
    private static final short SW_BAD_WRAPPED_KEY      = (short)0x9C20;

    // * Wrapped Key failed verify
    private static final short SW_BAD_ALGID_FOR_KEY    = (short)0x9C21;

    // * Wrapped Key failed verify
    private static final short SW_BAD_WRAPPED_PRIV_KEY = (short)0x9C22;

    // * For debugging purposes
    private static final short SW_INTERNAL_ERROR	= (short)0x9CFF;

    private static final byte ALG_RSA     = 0;
    private static final byte ALG_RSA_CRT = 1;
    private static final byte ALG_DSA     = 2;
    private static final byte ALG_DES     = 3;
    private static final byte ALG_3DES    = 4;
    private static final byte ALG_3DES3   = 5;
    
    private static final byte KEY_RSA_PUBLIC      = 1;
    private static final byte KEY_RSA_PRIVATE     = 2;
    private static final byte KEY_RSA_PRIVATE_CRT = 3;
    private static final byte KEY_DSA_PUBLIC      = 4;
    private static final byte KEY_DSA_PRIVATE     = 5;
    private static final byte KEY_DES             = 6;
    private static final byte KEY_3DES            = 7;
    private static final byte KEY_3DES3           = 8;
    private static final byte KEY_RSA_PKCS8_PAIR  = 9;

    private static final byte BLOB_ENC_PLAIN = 0;

    private static final byte OP_INIT     = 1;
    private static final byte OP_PROCESS  = 2;
    private static final byte OP_FINALIZE = 3;
    private static final byte OP_ONE_STEP = 4;

    private static final byte CD_SIGN    = 1;
    private static final byte CD_VERIFY  = 2;
    private static final byte CD_ENCRYPT = 3;
    private static final byte CD_DECRYPT = 4;

    private static final byte CM_RSA_NOPAD     =  0;
    private static final byte CM_RSA_PAD_PKCS1 =  1;
    private static final byte CM_DSA_SHA       = 16;
    private static final byte CM_DES_CBC_NOPAD = 32;
    private static final byte CM_DES_ECB_NOPAD = 33;

    private static final byte DL_APDU   = 1;
    private static final byte DL_OBJECT = 2;

    /**
     * List option
     */
    private static final byte LIST_OPT_RESET = 0;
    private static final byte LIST_OPT_NEXT  = 1;

    private static final byte OPT_DEFAULT     = 0;
    private static final byte OPT_RSA_PUB_EXP = 1;
    private static final byte OPT_DSA_GPQ     = 2;

    private static final short OFFSET_GENKEY_ALG            =  5;
    private static final short OFFSET_GENKEY_SIZE           =  6;
    private static final short OFFSET_GENKEY_PRV_ACL	    =  8;
    private static final short OFFSET_GENKEY_PUB_ACL	    = 14;
    private static final short OFFSET_GENKEY_OPTIONS	    = 20;
    private static final short OFFSET_GENKEY_RSA_PUB_EXP_LENGTH = 21;
    private static final short OFFSET_GENKEY_RSA_PUB_EXP_VALUE  = 23;
    private static final short OFFSET_GENKEY_DSA_GPQ	    = 21;

    private static final short KEYBLOB_OFFSET_ENCODING	  =  0;
    private static final short KEYBLOB_OFFSET_KEY_TYPE	  =  1;
    private static final short KEYBLOB_OFFSET_KEY_SIZE	  =  2;
    private static final short KEYBLOB_OFFSET_KEY_DATA	  =  4;
    private static final short WRAPKEY_OFFSET_TYPE        =  4;
    private static final short WRAPKEY_OFFSET_SIZE        =  5;
    private static final short WRAPKEY_OFFSET_DATA        =  6;

    private static final short OFFSET_IMP_KEY_ENC_WRAP_KEY      =  5;

    private static final short MAX_RSA_MOD_BITS  = 2048;
    private static final short MAX_RSA_MOD_BYTES = 256;

    // 554 = 2 bytes for explicit length, 
    //     512 bytes for data
    //      40 bytes for two sha digest buffers.
    //private static final short IOBUF_ALLOC = 554;
    private static final short IOBUF_ALLOC =  900;
    // offsets in iobuf used by CryptProcessFinal()
    private static final short VFY_OFF   =  450;
    private static final short VFY_MD_0  = 714;
    private static final short VFY_MD_1  = 734;

    // how many ms to delay when a bad password is detected
    private static final short BAD_PASSWD_DELAY = 1000; 

    // PKCS #8 RSA oid.
    private static final byte pkcs8_RSA_oid[] = {
       0x06, 0x09, // OID tag (9 bytes)
       0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x01, 0x01
    };
    private static final short pkcs8_RSA_oid_size = 11;

    // PKCS #1 SHA1 encoding header (DER).
    private static final byte sha1encode[] = {
       // SEQUENCE 33 bytes
       0x30,  0x21,
         // alogirthm ID (Sequence, 9 bytes)
         0x30, 0x09,
           // OID tag (5 bytes)
           0x06, 0x05,
             // sha1 oid 1.3.14.3.2.26
             0x2b, 0x0e, 0x03, 0x02, 0x1a,
           // paremeter = NULL
           0x05, 0x00,
         // the actual hash (OCTECT, 20 bytes)
	0x04, 0x14
	// Hash goes here
    };
    private static final short sha1encodeLen = 15;

    /**
     * Instance variable primitive declarations  ALL PERSISTENT MEMORY
     */
    private byte          pinEnabled;
    private byte          isWritable;
    private short         create_object_ACL;
    private short         create_key_ACL;
    private short         create_pin_ACL;
    private byte          enable_ACL_change;
    private MessageDigest shaDigest;
    private boolean       transientInit;
    private RandomData    randomGenerator;
    private Cipher	  des;
    private ASN1	  asn1;
    /* these values candidates for Transient objects */
    private short         authenticated_id; /* high */
    private short         nonce_ids;        /* high */
    private short         iobuf_size;       /* medium */
    private byte          key_it;           /* low */
    private byte          channelID;        /* low */

    /**
     * Instance variable objects and array declarations - PERSISTENT
     * Allocated by "new" calls below.
     */
    private MemoryManager mem;
    private ObjectManager om;

    private Cipher[]      ciphers;        // persistent
    private KeyPair[]     keyPairs;       // persistent
    private Key[]         keys;           // persistent
    private byte[]        keyMate;        // persistent
    private OwnerPIN[]    pins;           // persistent
    private Signature[]   signatures;     // persistent
    private byte[]        default_nonce;  // persistent
    private byte[]        keyACLs;        // persistent
    private byte[]        keyTries;       // persistent
    private byte[]        issuerInfo;     // persistent


    /**
     * Instance variable array declarations - TRANSIENT
     * Allocated by JCSystem.makeTransientXxxxxArray calls below.
     */

    private boolean[]     cardResetProcessed; // transient 1-entry array
    private byte[]        ciph_dirs;	      // transient
    private byte[]        iobuf;              // transient
    private byte[]        nonce;              // transient
    private short[]       loginCount;         // transient


    private CardEdge(byte bArray[], short bOffset, byte bLength)
    {
	//
	// In the future, we may want to allow the RA to change these 
	//  values on the fly?
	//
	// initialize the parameters to their default values

        //Save offset of the instance aid length.
        byte remainingLength = bLength;

	short mem_size = (short)5000;
	create_object_ACL = RA_ACL;
	create_key_ACL = RA_ACL;
	create_pin_ACL = RA_ACL;
	enable_ACL_change = 0; // can't change ACLs by default


        pins          = new OwnerPIN  [MAX_NUM_PINS];
        keys          = new Key       [MAX_NUM_KEYS];
        keyMate       = new byte      [MAX_NUM_KEYS];
        keyACLs       = new byte      [MAX_NUM_KEYS * KEY_ACL_SIZE];
        keyTries      = new byte      [MAX_NUM_KEYS];
        keyPairs      = new KeyPair   [MAX_NUM_KEYS];
        ciphers       = new Cipher    [MAX_NUM_KEYS];
        signatures    = new Signature [MAX_NUM_KEYS];
        default_nonce = new byte      [NONCE_SIZE];
        issuerInfo    = new byte      [ISSUER_INFO_SIZE];

        for (byte i = 0; i < MAX_NUM_KEYS; i++) {
            keyTries[i] = MAX_KEY_TRIES;
            keyMate[i]  =  -1;
        }

        Util.arrayFillNonAtomic(default_nonce, ZEROS, NONCE_SIZE, ZEROB);
        Util.arrayFillNonAtomic(issuerInfo, ZEROS,ISSUER_INFO_SIZE, ZEROB);

        byte appDataLen = 0;
        byte issuerLen = 0;

        //Attempt to parse app specific initialization data
        //Format
        //  n bytes- System header data, skip past to get to app data
        //  App specific data
        //  1 byte - Issuer Info Len
        //  n bytes- Issuer Info Value, string of characters
        //  1 byte - Custem memory size Len, agree upon 2
        //  2 bytes- Custom memory size value
        //  1 byte - Applet bit mask Len, now only handle 1, allow for more in future
        //  n bytes- Applet bit mask value. Process 1 now.


        //Skip past the header data provided by the system 
        
        //Get instance AID length

        byte len = bArray[bOffset];

        short customMemSize = 0;
        do {

            if(remainingLength <= 0)   {
                break;
            }

            if( len >  remainingLength) {
                break;
            }

            //Skip past the instance AID
            //
            bOffset+= len + 1;
            remainingLength-= (len + 1);

            if(remainingLength <= 0)   {
                break;
            }
        
            //Get app privileges length

            len = bArray[bOffset];

            if(len > remainingLength)   {
                break;
            }
            //Skip past the app privileges

            bOffset+= len + 1;
            remainingLength-=(len + 1);

            if(remainingLength <= 0)   {
                break;
            }

            //Get length of the entire application specific data block

            appDataLen = bArray[bOffset];

            if( appDataLen > remainingLength)
            {
                break;
            }  
            
            bOffset +=1;
            remainingLength=appDataLen;

            if(remainingLength <= 0)   {
                break;
            }

            //Get the issuer info length

            issuerLen  = bArray[bOffset];

            if(issuerLen > remainingLength)    {
                break;
            }

            bOffset++;
            remainingLength--;
            
            if(remainingLength <= 0)   {
               break;
            }

            //Actually copy our issuer info data

            if(issuerLen != 0) {
                if((short) issuerLen < ISSUER_INFO_SIZE) {
                    Util.arrayCopyNonAtomic(bArray,bOffset,issuerInfo,ZEROB,issuerLen);
                } else    {
                    break;
                }
            }

            //skip past the issuer data if any

            bOffset+= issuerLen ;
            remainingLength-= issuerLen;
            if(remainingLength <= 0)   {
                break;
            }

            //Get memory size length

            byte memSizeLen= bArray[bOffset];

            if(memSizeLen > remainingLength)   {
                break;
            }

            bOffset+=1;
            remainingLength-=1;
            if(remainingLength <= 0)   {
                break;
            }

            //allow configuration of the mem_size, since it can't be changed
            //on the fly.
            //Get memory size from  next block,assume 2 bytes 

            if(memSizeLen == 2)    {
                customMemSize = Util.makeShort(bArray[bOffset],bArray[(short) (bOffset + 1)]);
                bOffset += 2;
                remainingLength-=2;
            }

            //Sanity check the mem size

            if(customMemSize > 0)    {
                mem_size = (short) customMemSize ;
            }	

            if(remainingLength <= 0)   {
                break;
            }

            //obtain the  applet bit mask to alter the behavior as needed
            //only pay attention to first byte now.

            byte appletBitMask = 0;
            byte bitMaskLen = 0; 

            bitMaskLen =  bArray[bOffset];

            if(bitMaskLen > remainingLength)    {
                break;
            }
 
            if(bitMaskLen > 0)    {
                bOffset += 1;
                remainingLength-=1;
                appletBitMask = bArray[bOffset];
            }

            if(remainingLength <= 0)   {
              break;
            }

            //The first thing in the bitmask we support is allowing the change of ACL's
        
            if(appletBitMask != 0)    { 
                enable_ACL_change = (byte)(appletBitMask & 0x1);
            }

        } while(false);

        //Memory Management data instantiation

        mem           = new MemoryManager(mem_size);
        om            = new ObjectManager(mem);


	authenticated_id = 0;
	nonce_ids = 0;
	pinEnabled = 0;
        isWritable = 0;

	randomGenerator = null;
	shaDigest = null;
	des = null;

	transientInit = false;

    }

    private void delay(short delayTime) {
	short i;
	if (randomGenerator == null) {
	    randomGenerator = 
		RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}
	delayTime = (short)(delayTime >> 2);
	for (i=0; i < delayTime; i++) {
	    /* take about 4 ms */
	    randomGenerator.generateData(iobuf, VFY_MD_1, (short)4);
	}
    }

    private void ChangePIN(APDU apdu, byte buffer[])
    {
	byte pin_nb = buffer[ISO7816.OFFSET_P1];

	if (pin_nb < 0 || pin_nb >= MAX_NUM_PINS)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	OwnerPIN pin = pins[pin_nb];
	if (pin == null)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	if (buffer[ISO7816.OFFSET_P2] != 0)
	    ISOException.throwIt(SW_INCORRECT_P2);
	
	short avail = Util.makeShort(ZEROB, buffer[ISO7816.OFFSET_LC]);
	if (apdu.setIncomingAndReceive() != avail)
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	
	if (avail < 4)
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	byte pin_size = buffer[ISO7816.OFFSET_CDATA];
	if (avail < (short)(1 + pin_size + 1))
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	if (!CheckPINPolicy(buffer, (short)6, pin_size))
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	byte new_pin_size = buffer[(short)(6 + pin_size)];
	if (avail < (short)(1 + pin_size + 1 + new_pin_size))
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	if (!CheckPINPolicy(buffer, (short)(6 + pin_size + 1), new_pin_size))
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	if (pin.getTriesRemaining() == 0)
	    ISOException.throwIt(SW_IDENTITY_BLOCKED);
	
	if (!pin.check(buffer, (short)6, pin_size))
	{
	    LogoutAllIdentity(pin_nb);
	    delay(BAD_PASSWD_DELAY);
	    ISOException.throwIt(SW_AUTH_FAILED);
	}
	pin.update(buffer, (short)(6 + pin_size + 1), new_pin_size);
	LogoutAllIdentity(pin_nb);
    }

    /**
     * Checks if PIN policies are satisfied for a PIN code
     */
    private boolean CheckPINPolicy(byte pin_buffer[], short pin_offset, 
				   byte pin_size)
    {
	return pin_size >= pinMinSize && pin_size <= pinMaxSize;
    }

    /***********************************************************************/
    private void doDigest(byte[] inBuf, short inOff, short inLen,
			  byte[] outBuf, short outOff)
    {
	if (shaDigest == null) {
	    shaDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
	}
	shaDigest.reset();
	shaDigest.doFinal(inBuf, inOff, inLen, outBuf, outOff);
    }

    /***********************************************************************
     * Subroutines for ComputeCrypt APDU handler
     */

    private void CryptInit(APDU apdu, byte buffer[], short bytesLeft)
    {
	if (bytesLeft < 3) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    return;
	}

	byte key_nb	= buffer[ISO7816.OFFSET_P1];
	byte op	    = buffer[ISO7816.OFFSET_P2];
	byte ciph_mode     = buffer[ISO7816.OFFSET_CDATA];
	byte ciph_dir      = buffer[ISO7816.OFFSET_CDATA+1];
	byte data_location = buffer[ISO7816.OFFSET_CDATA+2];
	byte[] src_buf;
	short src_base;
	short src_avail;
	    
	switch(data_location) {
	case DL_APDU:
	    src_buf = buffer;
	    src_base = ISO7816.OFFSET_CDATA + 3;
	    src_avail = (short)(bytesLeft - 3);
	    break;

	case DL_OBJECT:
	    src_buf = iobuf;
	    src_base = 0;
	    src_avail = iobuf_size;
	    break;

	default:
	    ISOException.throwIt(SW_LOCATION_INVALID);
	    return;
	}
	    
	if (src_avail < 2) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    return;
	}
	    
	short size = Util.getShort(src_buf, src_base);
	if (src_avail < (short)(2 + size)) {
	    ISOException.throwIt(SW_DATA_CHUNK_SIZE_ERROR);
	    return;
	}

	Key key = keys[key_nb];
	ciph_dirs[key_nb] = ciph_dir;

	switch(ciph_dir) {
	case CD_SIGN:
	case CD_VERIFY:
	    ISOException.throwIt(SW_DIRECTION_UNSUPPORTED);
	    return;

	case CD_ENCRYPT:
	case CD_DECRYPT:
	  {
	    byte    ciph_alg_id;
	    byte    keyType      = key.getType();
	    boolean ignoreSize   = false;

	    switch (keyType) {
	    case KeyBuilder.TYPE_RSA_PUBLIC:
	    case KeyBuilder.TYPE_RSA_PRIVATE:
	    case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
		if (op == OP_ONE_STEP) {
		    size = 0;   // ignore input buffer
		} else if (size != 0) {
		    ISOException.throwIt(SW_DATA_CHUNK_SIZE_ERROR);
		    return;
		}
		if (key.getSize() > MAX_RSA_MOD_BITS) {
		    ISOException.throwIt(SW_KEY_SIZE_ERROR);
		    return;
		}
		if (ciph_mode == CM_RSA_NOPAD) {
		    ciph_alg_id = Cipher.ALG_RSA_NOPAD;
		} else if (ciph_mode == CM_RSA_PAD_PKCS1) {
//		    ciph_alg_id = Cipher.ALG_RSA_PKCS1;
		    ISOException.throwIt(SW_CIPH_MODE_UNSUPPORTED);
		    return;
		} else {
		    ISOException.throwIt(SW_CIPH_MODE_INVALID);
		    return;
		}
		break;

	    case KeyBuilder.TYPE_DES:
// XXX Check the validity of "size" here.
//		if (ciph_mode == CM_DES_CBC_NOPAD) {
//		    ciph_alg_id = Cipher.ALG_DES_CBC_NOPAD;
//		} else if (ciph_mode == CM_DES_ECB_NOPAD) {
//		    ciph_alg_id = Cipher.ALG_DES_ECB_NOPAD;
//		} else {
//		    ISOException.throwIt(SW_CIPH_MODE_INVALID);
//		    return;
//		}
//		break;

	    case KeyBuilder.TYPE_DSA_PUBLIC:
	    case KeyBuilder.TYPE_DSA_PRIVATE:
		ISOException.throwIt(SW_KEY_TYPE_UNSUPPORTED);
		return;
	    default:
		ISOException.throwIt(SW_KEY_TYPE_INVALID);
		return;
	    }
		
	    Cipher ciph = getCipher(key_nb, ciph_alg_id);
		
	    if (size == 0)
		ciph.init(key, (byte)(ciph_dir == CD_ENCRYPT 
			       ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT));
	    else
		ciph.init(key, (byte)(ciph_dir == CD_ENCRYPT 
			       ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT), 
			  src_buf, (short)(src_base + 2), size);
	  }
	  break;

	default:
	    ISOException.throwIt(SW_DIRECTION_INVALID);
	    break;
	}
    }

    private boolean EnDeCryptProcessFinal(APDU apdu, byte buffer[], 
					  short bytesLeft)
    {
	byte    key_nb   = buffer[ISO7816.OFFSET_P1];
	byte    op       = buffer[ISO7816.OFFSET_P2];
	byte    ciph_dir = ciph_dirs[key_nb];
	Key     key      = keys[key_nb];
	Cipher  ciph     = ciphers[key_nb];
	byte    data_location;
	byte[]  src_buf;
	byte[]  dst_buf;
	short   src_base = ISO7816.OFFSET_CDATA;
	short   dst_base = 2;
	short   src_avail;
	short   dst_len;
	short   dst_avail;
	boolean doubleCheck = false;

	if (ciph == null) {
	    ISOException.throwIt(SW_INCORRECT_P1);
	    return false;
	}

	if (op == OP_ONE_STEP) {
	    src_base  += 2;
	    bytesLeft -= 2;
	}

	// Did the APDU include enough data for the data_location?
	if (bytesLeft < 1) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    return false;
	}

	data_location = buffer[ src_base ];
	switch(data_location) {
	case DL_APDU: // write directy to the APDU
	    src_buf = buffer;
	    dst_buf = buffer;
	    src_base += 1;       // starts right after data_location
	    src_avail = (short)(bytesLeft - 1);
	    dst_avail = 255;  // usable bytes in APDU
	    break;

	case DL_OBJECT: // use heap object
	    src_buf = iobuf;
	    dst_buf = iobuf;
	    src_base = 0;
	    src_avail = iobuf_size;
	    dst_avail = 258; // 2 byte length + 256 byte data
	    break;

	default:
	    ISOException.throwIt(SW_LOCATION_INVALID);
	    return false;
	}
	if (src_avail < 2) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    return false;
	}

	short size = Util.getShort(src_buf, src_base);
	src_base += 2;
	if (src_avail < (short)(2 + size) || size < 0) {
	    ISOException.throwIt(SW_DATA_CHUNK_SIZE_ERROR);
	    return false;
	}
	// Now, check size against key length.
	byte keyType = key.getType();

	switch (keyType) {
	case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
	    if (ciph_dir == CD_ENCRYPT)
		doubleCheck = true;
	    // fall thru
	case KeyBuilder.TYPE_RSA_PUBLIC:
	case KeyBuilder.TYPE_RSA_PRIVATE:
	  {
	    if (op == OP_PROCESS) {
		ISOException.throwIt(SW_KEY_TYPE_UNSUPPORTED); // ambiguous?
		return false;
	    }
	    short keyBits = key.getSize();
	    if (keyBits > MAX_RSA_MOD_BITS) {
		ISOException.throwIt(SW_KEY_SIZE_ERROR);
		return false;
	    }

	    dst_len = (short)((short)(keyBits + 7) / 8) ;
	    byte  ciph_alg_id  = ciph.getAlgorithm();

	    // If we're not using padding, or if this is a decryption,
	    // then the input buffer must be the same size as the modulus.
	    if (ciph_alg_id == Cipher.ALG_RSA_NOPAD || 
		ciph_dir == CD_DECRYPT) {
		if (size != dst_len) {
		    ISOException.throwIt(SW_DATA_CHUNK_SIZE_ERROR);
		    return false;
		}
	    }

	    if (ciph_alg_id == Cipher.ALG_RSA_PKCS1) {
		if (ciph_dir == CD_ENCRYPT) {
		    // For encryption with PKCS#1 padding, the input buffer
		    // mustbe at least 11 bytes shorter than the modulus.
		    if (size > (short)(dst_len - 11)) {
			ISOException.throwIt(SW_DATA_CHUNK_SIZE_ERROR);
			return false;
		    }
		} else {
		    // For decryption with PKCS#1 padding, the output 
		    // will be at least 11 bytes shorter than input.
		    dst_len -= 11;
		}
	    }

	    // make sure there's enough room for the output.
	    if ((short)(2 + dst_len) > dst_avail) {
		ISOException.throwIt(SW_OUT_BUF_TOO_SMALL);
		return false;
	    }
	  }
	  break;

	case KeyBuilder.TYPE_DSA_PUBLIC:
	case KeyBuilder.TYPE_DSA_PRIVATE:
	    ISOException.throwIt(SW_KEY_TYPE_UNSUPPORTED);
	    return false;

	default:
	    ISOException.throwIt(SW_KEY_TYPE_INVALID);
	    return false;
	}


	if (op == OP_PROCESS) {
	    dst_len = ciph.update(src_buf, src_base, size, 
				  dst_buf, dst_base);
	} else {

	    if (doubleCheck) {
		doDigest(src_buf, src_base, size, iobuf, VFY_MD_0);
	    }

	    dst_len = ciph.doFinal(src_buf, src_base, size, 
				   dst_buf, dst_base);

	    if (doubleCheck) {
		// Use the public key to decrypt
		Key pubkey = keys[(short)keyMate[key_nb]];
		// setup cipher object for decrypt
		ciph.init(pubkey, Cipher.MODE_DECRYPT);
		// do a decrypt to the original source buffer
		short newsize = ciph.doFinal(dst_buf, dst_base, dst_len, 
					     iobuf, VFY_OFF);
		// should get back result of same length as original input
		if (size != newsize) {
		    ISOException.throwIt(SW_INTERNAL_ERROR); // unambiguous
		    return false;
		}
		doDigest(iobuf, VFY_OFF, size, iobuf, VFY_MD_1);
		// compare checksums of original and decrypted sources
		if (0 != Util.arrayCompare(iobuf, VFY_MD_0, 
					   iobuf, VFY_MD_1, (short)20 )) {
		    ISOException.throwIt(SW_SIGNATURE_INVALID); // unambiguous
		    return false;
		}
	    }
	}

	Util.setShort(dst_buf, ZEROS, dst_len);
	dst_len += 2;
	if (data_location == DL_OBJECT) {
	    iobuf_size = dst_len;
	} else {
	    if( dst_len > dst_avail ) {
		ISOException.throwIt(SW_OUT_BUF_TOO_SMALL);
		return false;
	    }
	    apdu.setOutgoingAndSend(ZEROS, dst_len);
	}

	return false;
    }

    private boolean CryptProcessFinal(APDU apdu, byte buffer[], short bytesLeft)
    {
	byte key_nb   = buffer[ISO7816.OFFSET_P1];
	byte ciph_dir = ciph_dirs[key_nb];

	switch(ciph_dir) {
	case CD_SIGN:
	case CD_VERIFY:
	    ISOException.throwIt(SW_DIRECTION_UNSUPPORTED);
	    break;

	case CD_ENCRYPT:
	case CD_DECRYPT:
	    return EnDeCryptProcessFinal(apdu, buffer, bytesLeft);

	default:
	    ISOException.throwIt(SW_DIRECTION_INVALID);
	    break;
	}
	return false;
    }

    /***********************************************************************
     * APDU handlers
     */
    private void ComputeCrypt(APDU apdu, byte buffer[])
    {
	short bytesLeft = (short)(0xff & buffer[ISO7816.OFFSET_LC]);

	byte key_nb = buffer[ISO7816.OFFSET_P1];
	if (key_nb < 0 || key_nb >= MAX_NUM_KEYS || keys[key_nb] == null) {
	    ISOException.throwIt(SW_INCORRECT_P1);
	}
	if (!authorizeKeyUse(key_nb)) {
	    ISOException.throwIt(SW_UNAUTHORIZED);
	}

	byte op = buffer[ISO7816.OFFSET_P2];
	boolean repeat = false;

	switch(op) {
	case OP_INIT:
	    CryptInit(apdu, buffer, bytesLeft);
	    break;

	case OP_PROCESS:
	case OP_FINALIZE:
	    do {
	      repeat = CryptProcessFinal(apdu, buffer, bytesLeft);
	    } while (repeat);
	    break;

	case OP_ONE_STEP:
	    CryptInit(apdu, buffer, bytesLeft);
	    repeat = CryptProcessFinal(apdu, buffer, bytesLeft);
	    break;

	default:
	    ISOException.throwIt(SW_INCORRECT_P2);
	    break;
	}
    }

    private void CreateObject(APDU apdu, byte buffer[])
    {
	short bytesLeft = Util.makeShort(ZEROB, buffer[ISO7816.OFFSET_LC]);
	boolean forceCreate = ((authenticated_id & RA_ACL) == RA_ACL);
	
	if ((authenticated_id & create_object_ACL) == 0)
	    ISOException.throwIt(SW_UNAUTHORIZED);
	
	if (bytesLeft != 14)
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	if (buffer[ISO7816.OFFSET_P1] != 0)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
	short obj_id = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+2));
	
	if (Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+4)) != 0 || 
				buffer[ISO7816.OFFSET_CDATA+6] < 0)
	    ISOException.throwIt(SW_NO_MEMORY_LEFT);
	
	short objlen = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+6));
	if( objlen <= 0 )
	    ISOException.throwIt(SW_INVALID_PARAMETER);

	if( obj_class == (short)0xffff && (obj_id == (short)0xffff || 
						obj_id == (short)0xfffe ) ) {
	    // I/O buffer
	    if( objlen > IOBUF_ALLOC )
		ISOException.throwIt(SW_NO_MEMORY_LEFT);
	    iobuf_size = objlen;
	} else {
	    if (om.exists(obj_class, obj_id)) {
		if( forceCreate ) {
		    om.destroyObject(obj_class, obj_id, true);
		} else {
		    ISOException.throwIt(SW_OBJECT_EXISTS);
		}
	    }
	    short size = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+6));
	    om.createObject(obj_class, obj_id, size,
			    buffer, (short)(ISO7816.OFFSET_CDATA+8));
	}
    }


    private void CreatePIN(APDU apdu, byte buffer[])
    {
	byte pin_nb = buffer[ISO7816.OFFSET_P1];
	byte num_tries = buffer[ISO7816.OFFSET_P2];

	if ((authenticated_id & create_pin_ACL) == 0 )
	    ISOException.throwIt(SW_UNAUTHORIZED);
	
	if (pin_nb < 0 || pin_nb >= MAX_NUM_PINS || pins[pin_nb] != null)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	byte avail = buffer[ISO7816.OFFSET_LC];
	
	if (avail < 1)
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	if (!CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, avail))
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	pins[pin_nb] = new OwnerPIN(num_tries, pinMaxSize);
	pins[pin_nb].update(buffer, ISO7816.OFFSET_CDATA, avail);
	pinEnabled = 1;
    }

    private void DeleteObject(APDU apdu, byte buffer[])
    {
	if (buffer[ISO7816.OFFSET_P1] != 0)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	if (buffer[ISO7816.OFFSET_P2] != 0 && buffer[ISO7816.OFFSET_P2] != 1)
	    ISOException.throwIt(SW_INCORRECT_P2);
	
	short bytesLeft = Util.makeShort(ZEROB, buffer[ISO7816.OFFSET_LC]);
	
	if (bytesLeft != 4)
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
	short obj_id = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+2));

	if( obj_class == -1 && (obj_id == -1 || obj_id == -2) ) {
	    // I/O Buffer
	    iobuf_size = 0;
	} else {
	    short base = om.getBaseAddress(obj_class, obj_id);
	
	    if (base == -1)
		ISOException.throwIt(SW_OBJECT_NOT_FOUND);
	
	    if (!om.authorizeDeleteFromAddress(base, authenticated_id))
		ISOException.throwIt(SW_UNAUTHORIZED);
	
	    om.destroyObject(obj_class, obj_id, buffer[ISO7816.OFFSET_P2] == 1);
	}
    }

    // Get the applet available memory
    private void GetMemory(APDU apdu, byte buffer[])
    {
//	short pos = 0;
//
//	// Sigh, these functions are appearantly not in the Axalto runtime
//
//	// Total object memory
//	// Persistant
//	Util.setShort(buffer, pos, ZEROS);
//	pos += 2;
//	Util.setShort(buffer, pos, ZEROS);
//	//Util.setShort(buffer, pos, 
//	//JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
//	pos += 2;
//
//	// Transient clear on reset
//	Util.setShort(buffer, pos, ZEROS);
//	pos += 2;
//	Util.setShort(buffer, pos, ZEROS);
//	//Util.setShort(buffer, pos, 
//	//JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
//	pos += 2;
//
//	// Transient clear on deselect
//	Util.setShort(buffer, pos, ZEROS);
//	pos += 2;
//	Util.setShort(buffer, pos, ZEROS);
//	//Util.setShort(buffer, pos, 
//	//JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
//	pos += 2;
//
//	// Send it...
//	apdu.setOutgoingAndSend(ZEROS, pos);
	    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    private void GetStatus(APDU apdu, byte buffer[])
    {
	if (buffer[ISO7816.OFFSET_P2] != 0)
	    ISOException.throwIt(SW_INCORRECT_P2);

	if (buffer[ISO7816.OFFSET_P1] == 1) {
	    GetMemory(apdu, buffer);
	    return;
	}

	if (buffer[ISO7816.OFFSET_P1] != 0)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	short pos = 0;
	
	buffer[pos++] = VERSION_PROTOCOL_MAJOR;
	buffer[pos++] = VERSION_PROTOCOL_MINOR;
	buffer[pos++] = VERSION_APPLET_MAJOR;
	buffer[pos++] = VERSION_APPLET_MINOR;

	// Total object memory
	Util.setShort(buffer, pos, ZEROS);
	pos += 2;
	Util.setShort(buffer, pos, (short)mem.getBuffer().length);
	pos += 2;

	Util.setShort(buffer, pos, ZEROS);
	pos += 2;
	Util.setShort(buffer, pos, mem.freemem());
	pos += 2;
	// transient

	// Number of PINs used
	byte cnt = 0;
	for(short i = 0; i < pins.length; i++)
	   if (pins[i] != null)
	       cnt++;

	buffer[pos++] = cnt;
 
	// Number of keys used
	cnt = 0;
	for(short i = 0; i < keys.length; i++)
	    if (keys[i] != null)
		cnt++;
 
	buffer[pos++] = cnt;

	// Logged identities
	Util.setShort(buffer, pos, nonce_ids);
	pos += 2;
	apdu.setOutgoingAndSend(ZEROS, pos);
    }

    private void importKeyBlob(byte key_nb, byte mate_nb, 
				byte[] buf, short offset, short avail) 
    {
	offset++;
	avail--;
	byte key_type = buf[offset];
	offset++;
	avail--;
	short key_size = Util.getShort(buf, offset);
	offset += 2;
	avail -= 2;
	
	switch(key_type)
	{
	    case KEY_RSA_PUBLIC:
	    {
		RSAPublicKey rsa_pub_key = 
 			(RSAPublicKey)getKey(key_nb, key_type, key_size);
 		if (avail < 2)
 		    ISOException.throwIt(SW_INVALID_PARAMETER);
 		
 		short size = Util.getShort(buf, offset);
 		offset += 2;
 		avail -= 2;
 		if (avail < (short)(size + 2))
 		    ISOException.throwIt(SW_INVALID_PARAMETER);
 		
 		rsa_pub_key.setModulus(buf, offset, size);
 		offset += size;
 		avail -= size;
 		size = Util.getShort(buf, offset);
 		offset += 2;
		avail -= 2;
 		if (avail < size)
 		    ISOException.throwIt(SW_INVALID_PARAMETER);
 		
 		rsa_pub_key.setExponent(buf, offset, size);
     
 		offset += size;
 		avail -= size;
     
 		break;
	    }
    
	    case KEY_RSA_PRIVATE:
	    {
		ISOException.throwIt(SW_KEY_TYPE_UNSUPPORTED);
		// fall through
// #ifdef notdef
// 		RSAPrivateKey rsa_prv_key = 
// 			 (RSAPrivateKey)getKey(key_nb, key_type, key_size);
// 		if (avail < 2)
// 		    ISOException.throwIt(SW_INVALID_PARAMETER);
//     
// 		short size = Util.getShort(buf, offset);
// 		offset += 2;
// 		avail -= 2;
// 		if (avail < (short)(size + 2))
// 		    ISOException.throwIt(SW_INVALID_PARAMETER);
// 		
// 		rsa_prv_key.setModulus(buf, offset, size);
// 		offset += size;
// 		avail -= size;
// 		size = Util.getShort(buf, offset);
// 		offset += 2;
// 		avail -= 2;
// 		if (avail < size)
// 		    ISOException.throwIt(SW_INVALID_PARAMETER);
// 		
// 		rsa_prv_key.setExponent(buf, offset, size);
// 		
// 		offset += size;
// 		avail -= size;
//     
// 		break;
// #endif
	    }
    
	    case KEY_RSA_PRIVATE_CRT:
	    {
		RSAPrivateCrtKey rsa_prv_key_crt = 
			(RSAPrivateCrtKey)getKey(key_nb, key_type, key_size);
		if (avail < 2)
		    ISOException.throwIt(SW_INVALID_PARAMETER);
		
		short size = Util.getShort(buf, offset);
		offset += 2;
		avail -= 2;
		if (avail < (short)(size + 2))
		    ISOException.throwIt(SW_INVALID_PARAMETER);
		
		rsa_prv_key_crt.setP(buf, offset, size);
    
		offset += size;
		avail -= size;
		size = Util.getShort(buf, offset);
		offset += 2;
		avail -= 2;
		if (avail < (short)(size + 2))
		    ISOException.throwIt(SW_INVALID_PARAMETER);
    
		rsa_prv_key_crt.setQ(buf, offset, size);
		
		offset += size;
		avail -= size;
		size = Util.getShort(buf, offset);
		offset += 2;
		avail -= 2;
		if (avail < (short)(size + 2))
		    ISOException.throwIt(SW_INVALID_PARAMETER);
    
		rsa_prv_key_crt.setPQ(buf, offset, size);
		
		offset += size;
		avail -= size;
		size = Util.getShort(buf, offset);
		offset += 2;
		avail -= 2;
		if (avail < (short)(size + 2))
		    ISOException.throwIt(SW_INVALID_PARAMETER);
		
		rsa_prv_key_crt.setDP1(buf, offset, size);
		
		offset += size;
		avail -= size;
		size = Util.getShort(buf, offset);
		offset += 2;
		avail -= 2;
		if (avail < size)
		    ISOException.throwIt(SW_IN_BUF_TOO_SMALL);
	    
		rsa_prv_key_crt.setDQ1(buf, offset, size);
	    
		offset += size;
		avail -= size;
		break;
	    }

	    case KEY_RSA_PKCS8_PAIR:
	    {
		RSAPrivateCrtKey rsa_prv_key_crt = (RSAPrivateCrtKey)
			getKey(key_nb, KEY_RSA_PRIVATE_CRT, key_size);
		RSAPublicKey rsa_pub_key = 
		     (RSAPublicKey)getKey(mate_nb, KEY_RSA_PUBLIC, key_size);
                short size, end;
		short base = offset;

		if (asn1 == null) {
		    asn1 = new ASN1();
		}

		avail += offset; /* convert avail from a size to and an end of
				  * buffer offset */
	
		// strip off the sequence
		offset = asn1.Unwrap(buf,offset,avail, (short)0); 
		avail = asn1.GetEnd();
		// skip the version
		offset = asn1.Skip(buf,offset,avail, (short)1);
		// fetch and check the oid
		offset = asn1.Unwrap(buf,offset,avail, (short)2);
		if (Util.arrayCompare(buf, offset, pkcs8_RSA_oid, ZEROS, 
					pkcs8_RSA_oid_size) != 0) {
		    ISOException.throwIt(SW_BAD_ALGID_FOR_KEY);
		}
		offset = asn1.GetNext();
		// fetch the key
		offset = asn1.Unwrap(buf,offset,avail, (short)3);
		avail = asn1.GetEnd();
		//offset = ASN1UnwrapBitString(buf,offset,avail, (short)4);
		// unwrap the SEQUENCE
		offset = asn1.Unwrap(buf, offset, avail, (short)5);
		avail = asn1.GetEnd();

		// skip the version
		offset = asn1.Skip(buf, offset, avail, (short)6);
		// fetch the modulus
		offset = asn1.Unwrap(buf, offset, avail, (short)7);
		end = asn1.GetEnd();
 		offset= asn1.Signed2Unsigned(buf, offset, end, (short)8);
		size = asn1.GetSize();
		rsa_pub_key.setModulus(buf, offset, size);
		offset = asn1.GetNext();
		// fetch the public exponent
		offset = asn1.Unwrap(buf, offset, avail, (short)9);
		end = asn1.GetEnd();
 		offset= asn1.Signed2Unsigned(buf, offset, end, (short)10);
		size = asn1.GetSize();
		rsa_pub_key.setExponent(buf, offset, size);
		offset = asn1.GetNext();
		// skip the private exponent
		offset = asn1.Skip(buf, offset, avail, (short)11);

		// fetch Prime 1
		offset = asn1.Unwrap(buf, offset, avail, (short)12);
		end = asn1.GetEnd();
 		offset= asn1.Signed2Unsigned(buf, offset, end, (short)13);
		size = asn1.GetSize();
		rsa_prv_key_crt.setP(buf, offset, size);
		offset = asn1.GetNext();
		// fetch Prime 2
		offset = asn1.Unwrap(buf, offset, avail, (short)14);
		end = asn1.GetEnd();
 		offset= asn1.Signed2Unsigned(buf, offset, end, (short)15);
		size = asn1.GetSize();
		rsa_prv_key_crt.setQ(buf, offset, size);
		offset = asn1.GetNext();
		// fetch exponent1
		offset = asn1.Unwrap(buf,offset,avail, (short)16);
		end = asn1.GetEnd();
 		offset= asn1.Signed2Unsigned(buf, offset, end, (short)17);
		size = asn1.GetSize();
		rsa_prv_key_crt.setDP1(buf, offset, size);
		offset = asn1.GetNext();
		// fetch exponent2
		offset = asn1.Unwrap(buf,offset,avail, (short)18);
		end = asn1.GetEnd();
 		offset= asn1.Signed2Unsigned(buf, offset, end, (short)19);
		size = asn1.GetSize();
		rsa_prv_key_crt.setDQ1(buf, offset, size);
		offset = asn1.GetNext();
		// fetch coefficent
		offset = asn1.Unwrap(buf,offset,avail, (short)20);
		end = asn1.GetEnd();
 		offset= asn1.Signed2Unsigned(buf, offset, end, (short)21);
		size = asn1.GetSize();
		rsa_prv_key_crt.setPQ(buf, offset, size);
		offset = asn1.GetNext();
		break;
	    }

	    case KEY_DES:
	    case KEY_3DES:
	    case KEY_3DES3:
// 	    {
// 		DESKey des_key = (DESKey)getKey(key_nb, key_type, key_size);
// 		if (avail < 2)
// 		    ISOException.throwIt(SW_INVALID_PARAMETER);
// 		short size = Util.getShort(buf, offset);
// 		offset += 2;
// 		avail -= 2;
// 		if (avail < size)
// 		    ISOException.throwIt(SW_INVALID_PARAMETER);
// 		des_key.setKey(buf, offset);
// 		offset += size;
// 		avail -= size;
// 		break;
// 	    }

	    case KEY_DSA_PUBLIC:
	    case KEY_DSA_PRIVATE:
	    {
		ISOException.throwIt(SW_KEY_TYPE_UNSUPPORTED);
		// fall through
	    }

	    default:
	    {
		ISOException.throwIt(SW_KEY_TYPE_INVALID);
		break;
	    }
	}
    }

    private void ImportKey(APDU apdu, byte buffer[])
    {
 	short bytesLeft = Util.makeShort(ZEROB, buffer[ISO7816.OFFSET_LC]);
 	
 	byte key_nb = buffer[ISO7816.OFFSET_P1];
 	byte mate_nb = buffer[ISO7816.OFFSET_P2];
 	short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
 	short obj_id = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+2));
         byte keybuf[];
         short keybuf_size;
         short base;
 	
 	if (key_nb < 0 || key_nb >= MAX_NUM_KEYS)
 	    ISOException.throwIt(SW_INCORRECT_P1);
 	
 	if (keys[key_nb] != null && keys[key_nb].isInitialized() && 
 	    !authorizeKeyWrite(key_nb))
 	    ISOException.throwIt(SW_UNAUTHORIZED);
 
 	if( obj_class == (short)0xffff && 
 		(obj_id == (short)0xffff || obj_id == (short)0xfffe ) ) {
 	    // I/O Object
 	    base = ZEROS;
 	    keybuf = iobuf;
 	    keybuf_size = iobuf_size;
 	} else {
 	    base = om.getBaseAddress(obj_class, obj_id);
 	    keybuf = mem.getBuffer();
 	    if (base == -1)
 		ISOException.throwIt(SW_OBJECT_NOT_FOUND);
 	    if (!om.authorizeReadFromAddress(base, authenticated_id))
 		ISOException.throwIt(SW_UNAUTHORIZED);
 
 	    keybuf_size = om.getSizeFromAddress(base);
 	}
 
 	if (keybuf_size < 4)
 	    ISOException.throwIt(SW_INVALID_PARAMETER);
 	
 	if (keybuf[base] != 0)
 	    ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
 
 	byte key_type = keybuf[(short)(base+KEYBLOB_OFFSET_KEY_TYPE)];
 
 	if (key_type == KEY_RSA_PKCS8_PAIR) {
 	    if (keys[mate_nb] != null && keys[mate_nb].isInitialized() && 
 	    				!authorizeKeyWrite(mate_nb))
 	        ISOException.throwIt(SW_UNAUTHORIZED);
 	    //
 	    // once we've paired up keys, make sure those keys are always
 	    // mated keys. This may be restrictive, but we already require
 	    // that once we create a key, that key must always have the same
 	    // key type, even if we overwrite it, so also requiring mated
 	    // keys to remain consistant is  a reasonable restriction.
 	    //
 	    if ( ((keyMate[mate_nb] != -1) 
 				&& (keyMate[mate_nb] != key_nb))
 	       || ((keyMate[key_nb] != -1) 
 				&& (keyMate[key_nb] != mate_nb)) ) {
 		ISOException.throwIt(SW_INCONSTANT_KEYPAIRING);
 	    }
 
 	    keyMate[mate_nb] = key_nb;
 	    keyMate[key_nb] = mate_nb;
   	}
 	importKeyBlob(key_nb, mate_nb, keybuf, base, keybuf_size);
 
 	// set the ACL value
 	Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA+4), keyACLs, 
 		      (short)(key_nb * KEY_ACL_SIZE), (short)KEY_ACL_SIZE);
 	if (key_type == KEY_RSA_PKCS8_PAIR) {
 	    // set ACL value on public key
 	    Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA+4+KEY_ACL_SIZE),
 	      keyACLs, (short)(mate_nb * KEY_ACL_SIZE), (short)KEY_ACL_SIZE);
         }
 
 	Util.arrayFillNonAtomic(keybuf, base, keybuf_size, ZEROB);
    }


    private void ListKeys(APDU apdu, byte buffer[])
    {
	if (buffer[ISO7816.OFFSET_P2] != 0)
	    ISOException.throwIt(SW_INCORRECT_P2);
	short expectedBytes = Util.makeShort(ZEROB, buffer[ISO7816.OFFSET_LC]);
	if (expectedBytes != 11)
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	if (buffer[ISO7816.OFFSET_P1] == 0)
	    key_it = 0;
	else
	if (buffer[ISO7816.OFFSET_P1] != 1)
	    ISOException.throwIt(SW_INCORRECT_P1);
	for(; key_it < MAX_NUM_KEYS && (keys[key_it] == null || 
	      !keys[key_it].isInitialized()); key_it++);
	if (key_it < MAX_NUM_KEYS)
	{
	    Key key = keys[key_it];
	    buffer[0] = key_it;
	    buffer[1] = getKeyType(key);
	    buffer[2] = keyMate[key_it];
	    Util.setShort(buffer, (short)3, key.getSize());
	    Util.arrayCopyNonAtomic(keyACLs, (short)(key_it * KEY_ACL_SIZE), 
		    buffer, ISO7816.OFFSET_CDATA, (short)KEY_ACL_SIZE);
	    key_it++;
	    apdu.setOutgoingAndSend((short)0, (short)11);
	}
    }

    private void ListObjects(APDU apdu, byte buffer[])
    {
	if (buffer[ISO7816.OFFSET_P2] != 0)
	    ISOException.throwIt(SW_INCORRECT_P2);
	
	byte expectedBytes = buffer[ISO7816.OFFSET_LC];
	
	if (expectedBytes < 14)
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	
	boolean found = false;
	
	if (buffer[ISO7816.OFFSET_P1] == 0)
	    found = om.getFirstRecord(buffer, ZEROS);
	else
	if (buffer[ISO7816.OFFSET_P1] != 1)
	    ISOException.throwIt(SW_INCORRECT_P1);
	else
	    found = om.getNextRecord(buffer, ZEROS);
	if (found)
	    apdu.setOutgoingAndSend((short)0, (short)14);
	else
	    ISOException.throwIt(SW_SEQUENCE_END);
    }

    private void ListPINs(APDU apdu, byte buffer[])
    {
	if (buffer[ISO7816.OFFSET_P1] != 0)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	if (buffer[ISO7816.OFFSET_P2] != 0)
	    ISOException.throwIt(SW_INCORRECT_P2);
	
	byte expectedBytes = buffer[ISO7816.OFFSET_LC];
	
	if (expectedBytes != 2)
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	
	short mask = 0;
	
	for(short b = 0; b < MAX_NUM_PINS; b++)
	    if (pins[b] != null)
		mask |= (short)(1 << b);

	Util.setShort(buffer, (short)0, mask);
	apdu.setOutgoingAndSend((short)0, (short)2);
    }

    private void ReadObject(APDU apdu, byte buffer[])
    {
	if (buffer[ISO7816.OFFSET_P1] != 0)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	if (buffer[ISO7816.OFFSET_P2] != 0)
	    ISOException.throwIt(SW_INCORRECT_P2);
	
	short bytesLeft = Util.makeShort(ZEROB, buffer[ISO7816.OFFSET_LC]);
	
	if (bytesLeft != 9)
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
	short obj_id    = Util.getShort(buffer, (short)7);
	short offset    = Util.getShort(buffer, (short)11);
	short size      = Util.makeShort(ZEROB, buffer[13]);
	byte[] buf;
	short base;
	if( offset < 0 || size < 0 )
	    ISOException.throwIt(SW_INVALID_PARAMETER);

	if( obj_class == (short)0xffff && 
		(obj_id == (short)0xffff || obj_id == (short)0xfffe ) ) {
	    // I/O Buffer
	    buf = iobuf;
	    base = 0;
	    if( offset > iobuf_size || (short)(offset + size) > iobuf_size )
		ISOException.throwIt(SW_INVALID_PARAMETER);
	} else {
	    buf = mem.getBuffer();
	    base = om.getBaseAddress(obj_class, obj_id);
	
	    if (base == -1)
		ISOException.throwIt(SW_OBJECT_NOT_FOUND);
	
	    if (!om.authorizeReadFromAddress(base, authenticated_id))
		ISOException.throwIt(SW_UNAUTHORIZED);
	
	    if ((short)(offset + size) > om.getSizeFromAddress(base))
		ISOException.throwIt(SW_INVALID_PARAMETER);
	}
	
	sendData(apdu, buf, (short)(base + offset), size);
    }

    /**
     * Deletes and zeros the IO objects and throws the passed in
     * exception
     */
    private void ThrowDeleteObjects(short exception)
    {
	Util.arrayFillNonAtomic(iobuf, ZEROS, iobuf_size, ZEROB);
	ISOException.throwIt(exception);
    }


    private void VerifyPIN(APDU apdu, byte buffer[])
    {
	byte pin_nb = buffer[ISO7816.OFFSET_P1];
	
	if (pin_nb < 0 || pin_nb >= MAX_NUM_PINS)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	OwnerPIN pin = pins[pin_nb];
	
	if (pin == null)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	if (buffer[ISO7816.OFFSET_P2] != 0)
	    ISOException.throwIt(SW_INCORRECT_P2);
	
	short numBytes = Util.makeShort(ZEROB, buffer[ISO7816.OFFSET_LC]);
	
	if (numBytes != apdu.setIncomingAndReceive())
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

	// Attempt to turn off blocking, just use the verify timeout
	//if (pin.getTriesRemaining() == 0)
        //   ISOException.throwIt(SW_IDENTITY_BLOCKED);
	
	if (!CheckPINPolicy(buffer,ISO7816.OFFSET_CDATA,(byte)numBytes)
	  || !pin.check(buffer, ISO7816.OFFSET_CDATA, (byte)numBytes))
	{
	    LogoutAllIdentity(pin_nb);
	    delay(BAD_PASSWD_DELAY);
	    ISOException.throwIt(SW_AUTH_FAILED);
	}
	LoginIdentity(pin_nb);
	sendData(apdu, nonce, ZEROS, NONCE_SIZE);
    }

    private void WriteObject(APDU apdu, byte buffer[])
    {
	if (buffer[ISO7816.OFFSET_P1] != 0)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	if (buffer[ISO7816.OFFSET_P2] != 0)
	    ISOException.throwIt(SW_INCORRECT_P2);
	
	short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
	short obj_id = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+2));
	short offset = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+6));
	short size = Util.makeShort(ZEROB, buffer[ISO7816.OFFSET_CDATA+8]);
	short obj_size;
	short base;
	byte[] buf;

	if( offset < 0 || size < 0 )
	    ISOException.throwIt(SW_INVALID_PARAMETER);

	if( obj_class == (short)0xffff && 
		(obj_id == (short)0xffff || obj_id == (short)0xfffe ) ) {
	    // I/O Object
	    base = 0;
	    buf = iobuf;
            iobuf_size = (short) ( size + offset);
	    obj_size = iobuf_size; 
	} else {
	    base = om.getBaseAddress(obj_class, obj_id);
	    buf = mem.getBuffer();
	    if (base == -1)
		ISOException.throwIt(SW_OBJECT_NOT_FOUND);

	    if (!om.authorizeWriteFromAddress(base, authenticated_id))
		ISOException.throwIt(SW_UNAUTHORIZED);
	
	    obj_size = om.getSizeFromAddress(base);
	}
	if ( offset > obj_size || size > obj_size ||
		(short) (offset + size) > obj_size)
	    ISOException.throwIt(SW_INVALID_PARAMETER);

	Util.arrayCopyNonAtomic(buffer, (short)14, buf,
	    (short)(base+offset), size);
    }

    private void Logout(APDU apdu, byte[] buffer) 
    {
        //Disable exceptions below to appease Gemalto 64K USB key
	//byte lc = buffer[ISO7816.OFFSET_LC];
	//if( lc != 0 )
	//    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

	byte logoutID = buffer[ISO7816.OFFSET_P1];
	

       //if ((authenticated_id & (short)(1 << logoutID)) == 0) {
       //    ISOException.throwIt(SW_UNAUTHORIZED);
       //}

	LogoutOneIdentity(logoutID);
    }


    private void initializeUpdate(APDU apdu, byte[] buffer) 
    {
	short ins = buffer[ISO7816.OFFSET_INS];
	if( ins != INS_INIT_UPDATE ) {
	    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	}
	apdu.setIncomingAndReceive();

	ProviderSecurityDomain domain = OPSystem.getSecurityDomain();
	channelID = domain.openSecureChannel(apdu);

	short len = (short)(buffer[ISO7816.OFFSET_LC]&0xff);
	apdu.setOutgoing();
	apdu.setOutgoingLength(len);
	apdu.sendBytes(ISO7816.OFFSET_CDATA, len);
    }

    private void externalAuthenticate(APDU apdu, byte[] buffer) 
    {
	apdu.setIncomingAndReceive();
	ProviderSecurityDomain domain = OPSystem.getSecurityDomain();
	domain.verifyExternalAuthenticate(channelID, apdu);

	// According to the Global Platform programming guidelines,
	// we might need to verify the security level ourselves.
	// Secrity level 0: No secure messaging
	// Security level 1: Mac only
	// Security level 3: Encrypt and Mac
	//
	// While the security level appears to be a bit mask, only these
	// three levels are defined in the 2.01 Open Platform spec.
	// Global Platform 2.1 defines addional levels which mantains
	// this bit mask:
	//
	// Security level 16: Response Mac only
	// Security level 17: Response and Card Mac 
	// Security level 19: Response and Card Mac, Encrypt
	// 
	// Also, security levels 48, 49, and 51 are RFU. Since the applet
	// cannot do response Macs, we check the security level explicitly
	// rather than checking for the MACing bit.
	//
	if (( buffer[ISO7816.OFFSET_P1] != (byte) 0x01 ) &&
		( buffer[ISO7816.OFFSET_P1] != (byte) 0x03 )) {
	    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	}
    }

    private void verifySecureChannel(APDU apdu, byte[] buffer) {
	apdu.setIncomingAndReceive();
	ProviderSecurityDomain domain = OPSystem.getSecurityDomain();
	domain.unwrap(channelID, apdu);
	AuthenticateIdentity(RA_IDENTITY);
    }

    private void verifySecureNonce(APDU apdu, byte[] buffer) {
	short bytes = Util.makeShort(ZEROB,buffer[ISO7816.OFFSET_LC]);
	if (apdu.setIncomingAndReceive() != bytes) 
	   ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

	if (bytes < NONCE_SIZE) {
	    ISOException.throwIt(SW_UNAUTHORIZED);
	}
	short offset = (short) (ISO7816.OFFSET_CDATA + bytes - NONCE_SIZE);
	if (Util.arrayCompare(buffer, offset, default_nonce, ZEROS, 
						NONCE_SIZE) == 0) {
	    AuthenticateIdentity(DEFAULT_IDENTITY);
	} else if (Util.arrayCompare(buffer, offset, nonce, ZEROS,
						NONCE_SIZE) == 0) {
	    // in the future, we would have one nonce per identity. for
	    // now once an app logs in as one identity, it can be any identity
	    authenticated_id = nonce_ids;
	} else {
	    ISOException.throwIt(SW_UNAUTHORIZED);
	    //AuthenticateIdentity(DEFAULT_IDENTITY);
	}
	buffer[ISO7816.OFFSET_LC] = (byte) (bytes - NONCE_SIZE);
    }

    private void resetPIN(APDU apdu, byte[] buffer) {
	byte pin_nb = buffer[ISO7816.OFFSET_P1] ;

	if (pin_nb < 0 || pin_nb >= MAX_NUM_PINS)
	    ISOException.throwIt(SW_INCORRECT_P1);
	if( buffer[ISO7816.OFFSET_P2] != ZEROB )
	    ISOException.throwIt(SW_INCORRECT_P2);

	byte pinLen = buffer[ISO7816.OFFSET_LC];
	if( pinLen < ZEROB ) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	OwnerPIN pin = pins[pin_nb];
	if (pin == null)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	if( !CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, pinLen))
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	
	pin.resetAndUnblock();
	pin.update(buffer, ISO7816.OFFSET_CDATA, pinLen);
	LogoutAllIdentity(pin_nb);
    }

    private short outputRSAPublicKey(short key_nb, byte[] buf, short offset, short key_size) {
	buf[offset] = ZEROB; // plaintext
	offset++;
	buf[offset] = (byte) 1; // RSA public key
	offset++;
	Util.setShort(buf, offset, (short)(key_size)); // Key Size. 
	offset+=2;

	RSAPublicKey key = (RSAPublicKey) keys[key_nb];

    
	short modsize = key.getModulus(buf, (short)(offset+2));
	Util.setShort(buf, offset, modsize);
	offset += 2 + modsize;

	short expsize = key.getExponent(buf, (short)(offset + 2));
	Util.setShort(buf, offset, expsize);

	return (short) (8 + modsize + expsize);
    }

    

    private void startEnrollment(APDU apdu, byte[] buffer) {
	byte prv_key_nb = (byte) (buffer[ISO7816.OFFSET_P1] & 0xf);
	byte pub_key_nb = (byte) (buffer[ISO7816.OFFSET_P2] & 0xf);
	byte owner = (byte) ((buffer[ISO7816.OFFSET_P1] >> 4)  & 0xf) ;
	byte usage = (byte) ((buffer[ISO7816.OFFSET_P2] >> 4) & 0xf);
	short acl = 0;
        short key_size = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+1));

	if ((buffer[ISO7816.OFFSET_P1] == 0) 
					&& (buffer[ISO7816.OFFSET_P2] == 0)) {
	    // old style. set up old values.
	    prv_key_nb = 0;
	    pub_key_nb = 1;
	    owner = 0xf;
	    usage = 1;
	 }
	if (owner == 0xf) {
	   acl = ANY_ONE_ACL;
	} else if (owner < 0 || owner > MAX_NUM_PINS) {
	    ISOException.throwIt(SW_INCORRECT_P1);
	} else {
	   acl = (short) (1 << owner);
	}

	
	if (prv_key_nb < 0 || prv_key_nb >= MAX_NUM_KEYS)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	if (keys[prv_key_nb] != null && 
		keys[prv_key_nb].isInitialized() && 
		!authorizeKeyWrite(prv_key_nb))
	    ISOException.throwIt(SW_UNAUTHORIZED);

	if (pub_key_nb < 0 || pub_key_nb >= MAX_NUM_KEYS)
	    ISOException.throwIt(SW_INCORRECT_P2);
	
	if (keys[pub_key_nb] != null &&
		keys[pub_key_nb].isInitialized() && 
		!authorizeKeyWrite(pub_key_nb))
	    ISOException.throwIt(SW_UNAUTHORIZED);

	if( buffer[ISO7816.OFFSET_LC] != (byte) 23 ) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	ProviderSecurityDomain domain = OPSystem.getSecurityDomain();
	boolean verified = false;
	verified = domain.decryptVerifyKey(channelID, apdu, (short) 9);
	if (!verified) {
	    ISOException.throwIt(SW_BAD_WRAPPED_KEY);
	}

	GenerateKeyPairRSA(apdu, buffer, prv_key_nb, pub_key_nb, acl);

	// copy public key to output object
	short pubkeysize = outputRSAPublicKey(pub_key_nb, iobuf, (short)2, (short) key_size);
	short modsize = (short) ((short)key_size / (short) 8);

	Util.setShort(iobuf, ZEROS, pubkeysize);

	// Compute digest over public key and decrypted challenge.
	// Write the digest into the iobuf.
	Util.arrayCopyNonAtomic(buffer, (short)11, iobuf,
				(short)(2 + pubkeysize), (short)16);
	doDigest(iobuf, (short)2, (short)(16+pubkeysize),
		 iobuf, (short)(2+pubkeysize+modsize) );
	// Sign the digest, writing the signature over the digest in the iobuf
	short sigsize = handSign(prv_key_nb, iobuf, (short) (2+pubkeysize+modsize),
	    (short)shaDigest.getLength(), iobuf, (short)(2+pubkeysize+2), modsize);

	Util.setShort(iobuf, (short)(2 + pubkeysize), sigsize);

	iobuf_size = (short) (2 + pubkeysize + 2 + sigsize);

	Util.setShort(buffer, ZEROS, iobuf_size);
	apdu.setOutgoingAndSend(ZEROS, (short)2);

    }

    //
    // HandSign hard codes SHA1.
    //
    private short handSign(byte key_nb, byte inbuf[], short inOffset, 
			short len, byte outbuf[], short outOffset, short modsize)
    {
	short index;
	//
	// build the signed data
	//
	// Hard coded for SHA1
	index = (short)(outOffset+modsize-(short)20);
	Util.arrayCopyNonAtomic(inbuf, inOffset, outbuf, index, (short)20);
	index = (short) (index - sha1encodeLen);
	Util.arrayCopyNonAtomic(sha1encode,ZEROS,outbuf,index,sha1encodeLen);
	index = (short) (index -1 );
	outbuf[index] = 0;
	Util.arrayFillNonAtomic(outbuf,(short)(outOffset+2), 
		(short)(index-outOffset-2), (byte)0xff);
	outbuf[(short)(outOffset+1)] = 1;
	outbuf[outOffset] = 0;
	Cipher ciph = getCipher(key_nb, Cipher.ALG_RSA_NOPAD);
	ciph.init(keys[key_nb], (byte) Cipher.MODE_ENCRYPT);
	return ciph.doFinal(outbuf, outOffset, modsize, 
				   outbuf, outOffset);
    }
	

    private void GenerateKeyPairRSA(APDU apdu, byte buffer[],
	byte prv_key_nb, byte pub_key_nb, short prv_acl)
    {
	
	byte alg_id = buffer[ISO7816.OFFSET_CDATA];
	short key_size = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+1));
	byte options = buffer[ISO7816.OFFSET_CDATA+3];

	//
	// once we've paired up keys, make sure those keys are always
	// mated keys. This may be restrictive, but we already require
	// that once we create a key, that key must always have the same
	// key type, even if we overwrite it, so also requiring mated
	// keys to remain consistant is  a reasonable restriction.
	//
	if ( ((keyMate[pub_key_nb] != -1) 
				&& (keyMate[pub_key_nb] != prv_key_nb))
	   || ((keyMate[prv_key_nb] != -1) 
				&& (keyMate[prv_key_nb] != pub_key_nb)) ) {
	    ISOException.throwIt(SW_INCONSTANT_KEYPAIRING);
	}

	RSAPublicKey pub_key =
	    (RSAPublicKey)getKey(pub_key_nb, KEY_RSA_PUBLIC, key_size);
	PrivateKey prv_key =
	    (PrivateKey)getKey(prv_key_nb, KEY_RSA_PRIVATE_CRT, key_size);

	keyMate[pub_key_nb] = prv_key_nb;
	keyMate[prv_key_nb] = pub_key_nb;

	// set private key ACLs
	short index = (short) (prv_key_nb * KEY_ACL_SIZE);
	Util.setShort(keyACLs, index, (short) NO_ONE_ACL); 
	index += 2;
	// only RA may write
	Util.setShort(keyACLs, index, (short) RA_ACL);
	index += 2;
	Util.setShort(keyACLs, index, (short) prv_acl);

	// set public key ACLs
	index = (short) (pub_key_nb * KEY_ACL_SIZE);
	Util.setShort(keyACLs, index, (short) ANY_ONE_ACL); 
	index += 2;
	// only RA may write
	Util.setShort(keyACLs, index, (short) RA_ACL);
	index += 2;
	Util.setShort(keyACLs, index, (short) ANY_ONE_ACL); 

	if (pub_key.isInitialized())
	    pub_key.clearKey();

	if (keyPairs[pub_key_nb] == null && keyPairs[prv_key_nb] == null)
	{
	    keyPairs[pub_key_nb] = new KeyPair(pub_key, prv_key);
	    keyPairs[prv_key_nb] = keyPairs[pub_key_nb];
	} else if (keyPairs[pub_key_nb] != keyPairs[prv_key_nb])
	    ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);

	KeyPair kp = keyPairs[pub_key_nb];
	
	if (kp.getPublic() != pub_key || kp.getPrivate() != prv_key)
	    ISOException.throwIt(SW_INTERNAL_ERROR);
	
	kp.genKeyPair();
    }


    private void importKeyEncrypted(APDU apdu, byte[] buffer) 
    {
	byte prv_key_nb = (byte) (buffer[ISO7816.OFFSET_P1] & 0xf);
	byte pub_key_nb = (byte) (buffer[ISO7816.OFFSET_P2] & 0xf);
	byte owner = (byte) ((buffer[ISO7816.OFFSET_P1] >> 4)  & 0xf) ;
	byte usage = (byte) ((buffer[ISO7816.OFFSET_P2] >> 4) & 0xf);
	short acl = 0;
	short obj_class = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
	short obj_id = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA+2));
        byte keybuf[];
        short keybuf_size;
        short base;
	

	if (owner == 0xf) {
	   acl = ANY_ONE_ACL;
	} else if (owner < 0 || owner > MAX_NUM_PINS) {
	    ISOException.throwIt(SW_INCORRECT_P1);
	} else {
	   acl = (short) (1 << owner);
	}
	
	if (prv_key_nb < 0 || prv_key_nb >= MAX_NUM_KEYS)
	    ISOException.throwIt(SW_INCORRECT_P1);
	
	if (keys[prv_key_nb] != null && 
		keys[prv_key_nb].isInitialized() && 
		!authorizeKeyWrite(prv_key_nb))
	    ISOException.throwIt(SW_UNAUTHORIZED);

	if (pub_key_nb < 0 || pub_key_nb >= MAX_NUM_KEYS)
	    ISOException.throwIt(SW_INCORRECT_P2);
	
	if (keys[pub_key_nb] != null &&
		keys[pub_key_nb].isInitialized() && 
		!authorizeKeyWrite(pub_key_nb))
	    ISOException.throwIt(SW_UNAUTHORIZED);

	short available = Util.makeShort(ZEROB, buffer[ISO7816.OFFSET_LC]);

	if ( available <= WRAPKEY_OFFSET_DATA ) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	// length of DES3 key
	short desLength = Util.makeShort(ZEROB, buffer[ISO7816.OFFSET_CDATA+
							WRAPKEY_OFFSET_SIZE]);

	// Sigh, the token on supports DES2 keys.
	if ( desLength != (short) 16 ) {
	    ISOException.throwIt(SW_KEY_SIZE_ERROR);
	}

	// length of Check
	// 1 byte length
	// n-byte check value
	short checkOffset = (short)(WRAPKEY_OFFSET_DATA+
					(int)desLength);
	if ( available <= checkOffset ) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	short checkLength = Util.makeShort(ZEROB,
			buffer[(short)(ISO7816.OFFSET_CDATA+checkOffset)]);

	//iv
	short ivOffset = (short)(checkOffset + 1 + (int)checkLength);
	if ( available <= ivOffset ) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	short ivLength = Util.makeShort(ZEROB,
			buffer[(short)(ISO7816.OFFSET_CDATA+ivOffset)]);
        if ( available < (short)(ivOffset+1+ivLength) ) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
	if ( ivLength != 8) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); // wrong error code
	}
	ivOffset += ISO7816.OFFSET_CDATA;

	ProviderSecurityDomain domain = OPSystem.getSecurityDomain();

	boolean verified = false;
	verified = domain.decryptVerifyKey(channelID, apdu, 
				(short)(ISO7816.OFFSET_CDATA+4));
	if (!verified) {
	    ISOException.throwIt(SW_BAD_WRAPPED_KEY);
	}

	if( obj_class == (short)0xffff && 
		(obj_id == (short)0xffff || obj_id == (short)0xfffe ) ) {
	    // I/O Object
	    base = ZEROS;
	    keybuf = iobuf;
	    keybuf_size = iobuf_size;
	} else {
	    base = om.getBaseAddress(obj_class, obj_id);
	    keybuf = mem.getBuffer();
	    if (base == -1)
		ISOException.throwIt(SW_OBJECT_NOT_FOUND);
	    if (!om.authorizeReadFromAddress(base, authenticated_id))
	    	ISOException.throwIt(SW_UNAUTHORIZED);
	    // we clear the buffer at the end, so we also need write
	    // privellege
	    if (!om.authorizeWriteFromAddress(base, authenticated_id))
	    	ISOException.throwIt(SW_UNAUTHORIZED);

	    keybuf_size = om.getSizeFromAddress(base);
	}

        // name the key type (it's not encrypted, so we can grab it early */
	byte key_type = keybuf[(short)(base+KEYBLOB_OFFSET_KEY_TYPE)];

	// get the des key to decrypt the private key
        if (keybuf[base] == 0x01) { // BLOB_ENC_ENCRYPTED
	  DESKey des3 = (DESKey) KeyBuilder.buildKey(
		KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
	  des3.setKey(buffer,(short)(ISO7816.OFFSET_CDATA+WRAPKEY_OFFSET_DATA));

	  if (des == null) {
	    des = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
	    //ISOException.throwIt((short)2);
  	  }

	  // decrypt the private key
	  des.init(des3, Cipher.MODE_DECRYPT, buffer, 
					(short)(ivOffset+1), ivLength);
	  des.doFinal(keybuf, (short)(base+KEYBLOB_OFFSET_KEY_DATA),
			(short)(keybuf_size-KEYBLOB_OFFSET_KEY_DATA),
			keybuf, (short)(base+KEYBLOB_OFFSET_KEY_DATA));
        } else if (iobuf[0] != 0x00) {
	    ISOException.throwIt(SW_INVALID_PARAMETER);
        }

        // at this point the key is in the object buffer in the clear.
        // if anything goes wrong from here on out, we want to smash the 
        // data in the buf so the key doesn't get leaked.
        try {
	    if (key_type == KEY_RSA_PRIVATE || 
			key_type == KEY_RSA_PRIVATE_CRT || 
					key_type == KEY_RSA_PKCS8_PAIR) {
		//
		// once we've paired up keys, make sure those keys are always
		// mated keys. This may be restrictive, but we already require
		// that once we create a key, that key must always have the same
		// key type, even if we overwrite it, so also requiring mated
		// keys to remain consistant is  a reasonable restriction.
		//
		if ( ((keyMate[pub_key_nb] != -1) 
				&& (keyMate[pub_key_nb] != prv_key_nb))
		    || ((keyMate[prv_key_nb] != -1) 
				&& (keyMate[prv_key_nb] != pub_key_nb)) ) {
		    ISOException.throwIt(SW_INCONSTANT_KEYPAIRING);
		}

		keyMate[pub_key_nb] = prv_key_nb;
		keyMate[prv_key_nb] = pub_key_nb;
  	    }
	    // if it doesn't start with a sequence, it's not DER data,
	    // don't try to decode it.
	    if ((key_type == KEY_RSA_PKCS8_PAIR) && 
		(keybuf[(short)(base+KEYBLOB_OFFSET_KEY_DATA)] != 0x30)) {
		ISOException.throwIt(SW_BAD_WRAPPED_PRIV_KEY);
	    }
	    importKeyBlob(prv_key_nb, pub_key_nb, keybuf, base, keybuf_size);
	} finally {
	    // we're done with the keybuf, just clear it out now
	    Util.arrayFillNonAtomic(keybuf, base, keybuf_size, ZEROB);
	}

	// set private key ACLs
	short index = (short) (prv_key_nb * KEY_ACL_SIZE);
	Util.setShort(keyACLs, index, (short) NO_ONE_ACL); 
	index += 2;
	// only RA may write
	Util.setShort(keyACLs, index, (short) RA_ACL);
	index += 2;
	Util.setShort(keyACLs, index, (short) acl);
	if (key_type == KEY_RSA_PKCS8_PAIR) {
	    // set public key ACLs
	    index = (short) (pub_key_nb * KEY_ACL_SIZE);
	    Util.setShort(keyACLs, index, (short) ANY_ONE_ACL); 
	    index += 2;
	    // only RA may write
	    Util.setShort(keyACLs, index, (short) RA_ACL);
	    index += 2;
	    Util.setShort(keyACLs, index, (short) ANY_ONE_ACL); 
        }
    }

    private void readIOBuf(APDU apdu, byte buffer[]) {
// 
// 	byte p1 = buffer[ISO7816.OFFSET_P1];
// 	byte p2 = buffer[ISO7816.OFFSET_P2];
// 	byte lc = buffer[ISO7816.OFFSET_LC];
// 
// 	if( p2  != ZEROB )
// 	    ISOException.throwIt(SW_INCORRECT_P2);
// 
// 	if( lc != (byte) 2 )
// 	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
// 
// 	short offset = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
// 	short len = (short) (p1 & 0xff);
// 
// 	if( offset < (short)0 || len > iobuf_size || offset > iobuf_size ||
// 		(short)(len+offset) > iobuf_size )
// 	    ISOException.throwIt(SW_INVALID_PARAMETER);
// 
// 	Util.arrayCopyNonAtomic(iobuf, offset, buffer, ZEROS, len);
// 	apdu.setOutgoingAndSend(ZEROS, len);
	ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    private void getLifeCycle(APDU apdu, byte[] buffer) {
	byte lc = buffer[ISO7816.OFFSET_LC];
	buffer[0] = OPSystem.getCardContentState();
	if (lc == 1) {
	    // compatibility
	    apdu.setOutgoingAndSend(ZEROS, (short)1);
	} else {
	    buffer[1] = (byte)(pinEnabled + isWritable);
	    buffer[2] = VERSION_PROTOCOL_MAJOR;
	    buffer[3] = VERSION_PROTOCOL_MINOR;
	    apdu.setOutgoingAndSend(ZEROS, (short)4);
	}
    }

    private void setLifeCycle(APDU apdu, byte[] buffer) {
	byte lc = buffer[ISO7816.OFFSET_LC];
	if( lc != 0 )
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

	boolean result =
	    OPSystem.setCardContentState(buffer[ISO7816.OFFSET_P1]);

	if( result == false )
	    ISOException.throwIt(SW_INVALID_PARAMETER);
    }

    private void getIssuerInfo(APDU apdu, byte[] buffer) {
	short size = Util.makeShort(ZEROB,buffer[ISO7816.OFFSET_LC]);
	if (size != ISSUER_INFO_SIZE) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	Util.arrayCopyNonAtomic(issuerInfo, ZEROS, buffer, ZEROS, 
							ISSUER_INFO_SIZE);
        apdu.setOutgoingAndSend(ZEROS, ISSUER_INFO_SIZE);
    }

    private void setIssuerInfo(APDU apdu, byte[] buffer) {
	short size = Util.makeShort(ZEROB,buffer[ISO7816.OFFSET_LC]);
	if (size != ISSUER_INFO_SIZE) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA,
				 issuerInfo, ZEROS, ISSUER_INFO_SIZE);
    }

    private void getRandom(APDU apdu, byte[] buffer) {
	short len = Util.makeShort(ZEROB,buffer[ISO7816.OFFSET_LC]);
	if (randomGenerator == null) {
	    randomGenerator = 
		RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}
	randomGenerator.generateData(buffer, ZEROS, len);
        apdu.setOutgoingAndSend(ZEROS, len);
    }

    private void seedRandom(APDU apdu, byte[] buffer) {
	short len = Util.makeShort(ZEROB,buffer[ISO7816.OFFSET_LC]);
	if (randomGenerator == null) {
	    randomGenerator = 
		RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}
	randomGenerator.setSeed(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void getBuildID(APDU apdu, byte[] buffer) {
	short size = Util.makeShort(ZEROB,buffer[ISO7816.OFFSET_LC]);
	if (size < 4) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	Util.setShort(buffer, ZEROS, BUILDID_MAJOR);
	Util.setShort(buffer, (short)2, BUILDID_MINOR);
	apdu.setOutgoingAndSend(ZEROS, (short)4);
    }

    private void getBuiltInACL(APDU apdu, byte[] buffer) {
	if (buffer[ISO7816.OFFSET_LC] < (byte)7) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	Util.setShort(buffer, ZEROS, create_object_ACL);
	Util.setShort(buffer, (short)2, create_key_ACL);
	Util.setShort(buffer, (short)4, create_pin_ACL);
	buffer[6] = enable_ACL_change;
	apdu.setOutgoingAndSend(ZEROS, (short)7);
    }

    private void setBuiltInACL(APDU apdu, byte[] buffer) {
	if (buffer[ISO7816.OFFSET_LC] != (byte)7) {
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	// my default, the applet is completely locked down.
	if (enable_ACL_change == 0) {
	    ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
	}
	create_object_ACL = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
	create_key_ACL = Util.getShort(buffer,(short)(ISO7816.OFFSET_CDATA+2));
	create_pin_ACL = Util.getShort(buffer,(short)(ISO7816.OFFSET_CDATA+4));
	enable_ACL_change = buffer[ISO7816.OFFSET_CDATA+6];
	isWritable = 0;
	if (((create_object_ACL & 0xff) != 0) &&
	    			((create_key_ACL & 0xff) != 0)) {
	   isWritable = 2;
	}
    }

    /**
     * UTILITY FUNCTIONS
     */
    private void sendData(APDU apdu, byte data[], short offset, short size)
    {
	if (size > 255)
	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	Util.arrayCopyNonAtomic(data, offset, apdu.getBuffer(), ZEROS, size);
	apdu.setOutgoingAndSend(ZEROS, size);
    }

    private void LoginIdentity(byte id_nb)
    {
	if (Util.arrayCompare(nonce, ZEROS, default_nonce, ZEROS,
						 NONCE_SIZE) == 0) {
	    if (randomGenerator == null) {
		randomGenerator = 
		    RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	    }
	    randomGenerator.generateData(nonce, ZEROS, NONCE_SIZE);
	}
	nonce_ids |= (short)(1 << id_nb);
	loginCount[id_nb] += 1;
    }

    private void AuthenticateIdentity(byte id_nb)
    {
	authenticated_id |= (short)(1 << id_nb);
    }

    private void LogoutOneIdentity(byte id_nb)
    {
	// log out one app from this identity. when all identities have
	// been logged out, clean the nonce
	if (loginCount[id_nb] != 0) {
	    // never decrement past '0'
	    loginCount[id_nb] -=  1;
	}
	if (loginCount[id_nb] != 0) {
	    return;
	}
	nonce_ids &= ~(short)(1 << id_nb);
	pins[id_nb].reset();
	if (nonce_ids == 0) {
	    Util.arrayFillNonAtomic(nonce, ZEROS, NONCE_SIZE, ZEROB);
	}
    }

    private void LogoutAllIdentity(byte id_nb)
    {
	// log everyone off this identity
	loginCount[id_nb] = 0;
	LogoutOneIdentity(id_nb);
    }

    private void LogoutAll()
    {
	for(byte i = 0; i < MAX_NUM_PINS; i++)
	    if (pins[i] != null) {
		LogoutAllIdentity(i);
	    }
    }

    /**
     * Check from ACL if a key can be read
     */
    private boolean authorizeKeyRead(byte key_nb)
    {
	short acl_offset = (short)(key_nb * KEY_ACL_SIZE);
	short required_ids = Util.getShort(keyACLs, acl_offset);
	return (required_ids & authenticated_id) != 0;
    }

    /**
     * Check from ACL if a key can be used
     */
    private boolean authorizeKeyUse(byte key_nb)
    {
	short acl_offset = (short)(key_nb * KEY_ACL_SIZE + 4);
	short required_ids = Util.getShort(keyACLs, acl_offset);
	return (required_ids & authenticated_id) != 0;
    }

    /**
     * Check from ACL if a key can be overwritten
     */
    private boolean authorizeKeyWrite(byte key_nb)
    {
	short acl_offset = (short)(key_nb * KEY_ACL_SIZE + 2);
	short required_ids = Util.getShort(keyACLs, acl_offset);
	return (required_ids & authenticated_id) != 0;
    }

    private Cipher getCipher(byte key_nb, byte alg_id)
    {
	if (ciphers[key_nb] == null)
	    ciphers[key_nb] = Cipher.getInstance(alg_id, false);
	else
	if (ciphers[key_nb].getAlgorithm() != alg_id)
	    ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
	return ciphers[key_nb];
    }

    /**
     * Retrieves the Key object to be used w/ the specified key number,
     * key type (KEY_XX) and size.
     *
     * <p>If exists, check it has the proper key type * If not, creates
     * it.</p>
     *
     * @return Retrieved Key object
     * @throws SW_UNATUTHORIZED
     * @throws SW_OPERATION_NOT_ALLOWED
     */
    private Key getKey(byte key_nb, byte key_type, short key_size)
    {
	byte jc_key_type = keyType2JCType(key_type);
	if (keys[key_nb] == null)
	{
	    if (0 == (authenticated_id & create_key_ACL))
		ISOException.throwIt(SW_UNAUTHORIZED);
	    keys[key_nb] = KeyBuilder.buildKey(jc_key_type, key_size, false);
	} else
	if (keys[key_nb].getSize() != key_size 
		|| keys[key_nb].getType() != jc_key_type)
	    ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
	return keys[key_nb];
    }

    private byte getKeyType(Key key)
    {
	switch(key.getType())
	{
	case KeyBuilder.TYPE_RSA_PUBLIC:
	    return KEY_RSA_PUBLIC;

	case KeyBuilder.TYPE_RSA_PRIVATE:
	    return KEY_RSA_PRIVATE;

	case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
	    return KEY_RSA_PRIVATE_CRT;

	case ALG_DES:
	    if (key.getSize() == KeyBuilder.LENGTH_DES)
		return KEY_DES;
	    if (key.getSize() == KeyBuilder.LENGTH_DES3_2KEY)
		return KEY_3DES;
	    if (key.getSize() == KeyBuilder.LENGTH_DES3_3KEY)
		return KEY_3DES3;
	    break;
	}
	ISOException.throwIt(SW_KEY_TYPE_INVALID);
	return 0;
    }

    private Signature getSignature(byte key_nb, byte alg_id)
    {
	if (signatures[key_nb] == null)
	    signatures[key_nb] = Signature.getInstance(alg_id, false);
	else
	if (signatures[key_nb].getAlgorithm() != alg_id)
	    ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
	return signatures[key_nb];
    }

    public static void install(byte bArray[], short bOffset, byte bLength)
    {
	CardEdge wal = new CardEdge(bArray, bOffset, bLength);
	wal.register();
    }

    private byte keyType2JCType(byte key_type)
    {
	switch(key_type)
	{
	case KEY_RSA_PUBLIC:
	    return KeyBuilder.TYPE_RSA_PUBLIC;

	case KEY_RSA_PRIVATE:
	    return KeyBuilder.TYPE_RSA_PRIVATE;

	case KEY_RSA_PRIVATE_CRT:
	    return KeyBuilder.TYPE_RSA_CRT_PRIVATE;

	case KEY_DSA_PUBLIC:
	    ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
	    // fall through

	case KEY_DSA_PRIVATE: // '\005'
	    ISOException.throwIt(SW_UNSUPPORTED_FEATURE);
	    // fall through

	case KEY_DES:
	    return KeyBuilder.TYPE_DES;

	case KEY_3DES:
	case KEY_3DES3:
	    return KeyBuilder.TYPE_DES;

	default:
	    ISOException.throwIt(SW_INVALID_PARAMETER);
	    break;
	}
	return 0;
    }

    private void processCardReset() {
	LogoutAll();
	// This flag is CLEAR_ON_RESET, so it will be set to false when
	// the card is reset or removed.
	cardResetProcessed[0] = true;
    }

    private boolean requireAuth(byte ins)
    {
	boolean ret = false;
	switch (ins) {
	case INS_IMPORT_KEY:
	case INS_COMPUTE_CRYPT:
	case INS_CREATE_PIN:
	case INS_CREATE_OBJ:
	case INS_DELETE_OBJ:
	case INS_READ_OBJ:
	case INS_WRITE_OBJ:
//	case INS_LOGOUT:
	    ret = true;
	}
	return ret;
    }

    private void initTransient()
    {
	iobuf = JCSystem.makeTransientByteArray(IOBUF_ALLOC,
        		    JCSystem.CLEAR_ON_DESELECT);
	ciph_dirs = JCSystem.makeTransientByteArray(MAX_NUM_KEYS,
		    JCSystem.CLEAR_ON_DESELECT);
	//
	// before release we need to make sure that the nonce is
	// an array for each pin. (again memory size, but in this case
	// we are taking about 8->64 bytes, not trying to find another 1k
	// bytes.
	//
	nonce = JCSystem.makeTransientByteArray(NONCE_SIZE,
		    JCSystem.CLEAR_ON_RESET);
	loginCount = JCSystem.makeTransientShortArray(MAX_NUM_PINS,
		     JCSystem.CLEAR_ON_RESET);
	cardResetProcessed = JCSystem.makeTransientBooleanArray((short)1,
		    JCSystem.CLEAR_ON_RESET);
	transientInit = true;
    }

    //
    // handle non-secure standard commands. Called from process.
    //
    private void processCardEdgeAPDU(APDU apdu, byte buffer[])
    {
	byte ins = buffer[ISO7816.OFFSET_INS];

	if (requireAuth(ins)) {
	    verifySecureNonce(apdu, buffer);
	}

	switch(ins)
	{
	case INS_IMPORT_KEY:
	    ImportKey(apdu, buffer);
	    break;

	case INS_COMPUTE_CRYPT:
	    ComputeCrypt(apdu, buffer);
	    break;

	case INS_VERIFY_PIN:
	    VerifyPIN(apdu, buffer);
	    break;

	case INS_CREATE_PIN:
	    CreatePIN(apdu, buffer);
	    break;

	case INS_CHANGE_PIN:
	    ChangePIN(apdu, buffer);
	    break;

	case INS_CREATE_OBJ:
	    CreateObject(apdu, buffer);
	    break;

	case INS_DELETE_OBJ:
	    DeleteObject(apdu, buffer);
	    break;

	case INS_READ_OBJ:
	    ReadObject(apdu, buffer);
	    break;

	case INS_WRITE_OBJ:
	    WriteObject(apdu, buffer);
	    break;

	case INS_LOGOUT:
	    Logout(apdu,buffer);
	    break;

	case INS_LIST_PINS:
	    ListPINs(apdu, buffer);
	    break;

	case INS_LIST_OBJECTS:
	    ListObjects(apdu, buffer);
	    break;

	case INS_LIST_KEYS:
	    ListKeys(apdu, buffer);
	    break;

	case INS_GET_STATUS:
	    GetStatus(apdu, buffer);
	    break;

	case INS_GET_ISSUER_INFO:
	    getIssuerInfo(apdu, buffer);
	    break;

	case INS_GET_RANDOM:
	    getRandom(apdu, buffer);
	    break;

	case INS_SEED_RANDOM:
	    seedRandom(apdu, buffer);
	    break;

	case INS_GET_LIFECYCLE:
	    getLifeCycle(apdu, buffer);
	    break;

	case INS_GET_BUILDID:
	    getBuildID(apdu, buffer);
	    break;

        case INS_GET_BUILTIN_ACL:
	    getBuiltInACL(apdu, buffer);
	    break;


	case INS_NOP:
	    break;

//      case INS_SETUP:
//      case INS_GEN_KEYPAIR:
//      case INS_EXPORT_KEY:
//      case INS_LOGOUT_ALL:
//      case INS_GET_CHALLENGE:
//      case INS_CAC_EXT_AUTH:
//      case INS_UNBLOCK_PIN:
	default:
	    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	    break;
	}
    }

    //
    // handle non-secure standard commands. Called from process.
    //
    private void processSecureAPDU(APDU apdu, byte buffer[])
    {
	byte ins = buffer[ISO7816.OFFSET_INS];

	if (ins != INS_SEC_EXT_AUTH) {
	    verifySecureChannel(apdu, buffer);
	}

	switch (ins) {
	case INS_SEC_EXT_AUTH:
	    externalAuthenticate(apdu, buffer);
	    break;

	case INS_SEC_SET_PIN:
	    resetPIN(apdu, buffer);
	    break;

	case INS_SEC_START_ENROLLMENT:
	    startEnrollment(apdu, buffer);
	    break;
 
	case INS_SEC_IMPORT_KEY_ENCRYPTED:
	    importKeyEncrypted(apdu, buffer);
	    break;

	case INS_SEC_READ_IOBUF:
	    readIOBuf(apdu, buffer);
	    break;

	case INS_SEC_SET_LIFECYCLE:
	    setLifeCycle(apdu, buffer);
	    break;

	case INS_SEC_SET_ISSUER_INFO:
	    setIssuerInfo(apdu, buffer);
	    break;

	case INS_CREATE_OBJ:
	    CreateObject(apdu, buffer);
	    break;

	case INS_WRITE_OBJ:
	    WriteObject(apdu, buffer);
	    break;

	case INS_IMPORT_KEY:
	    ImportKey(apdu, buffer);
	    break;

	case INS_COMPUTE_CRYPT:
	    ComputeCrypt(apdu, buffer);
	    break;

	case INS_CREATE_PIN:
	    CreatePIN(apdu, buffer);
	    break;

	case INS_DELETE_OBJ:
	    DeleteObject(apdu, buffer);
	    break;

	case INS_READ_OBJ:
	    ReadObject(apdu, buffer);
	    break;

        case INS_SEC_SET_BUILTIN_ACL:
	    setBuiltInACL(apdu, buffer);
	    break;

	default:
	    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	}
    }

    //
    // **** Most processing starts here!!
    //
    public void process(APDU apdu)
    {
	if (selectingApplet())
	    ISOException.throwIt(ISO7816.SW_NO_ERROR);

	if (!transientInit) {
	    initTransient();
	}

	if ( !cardResetProcessed[0] ) {
	     processCardReset();
	}

	authenticated_id = 0;

	byte buffer[] = apdu.getBuffer();
	byte cla = buffer[ISO7816.OFFSET_CLA];

	switch (cla) {
	case ISO7816.CLA_ISO7816:
	case ISO7816.INS_SELECT:  // right value, but right define?
	    return;
	case CardEdge_CLA:
	    processCardEdgeAPDU(apdu,buffer);
	    break;
	case CardManager_CLA:
	    initializeUpdate(apdu, buffer);
	    break;
	case SECURE_CLA:
	    processSecureAPDU(apdu,buffer);
	    break;
	default:
	    ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	}
    
    }
}

