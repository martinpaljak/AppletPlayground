// --------------------------------------------------------------------------- 
// Protocol for Lightweight Authentication of Identity (PLAID)
// 
// Cardholder applet
// 
// Reference Implementation compliant with AS 5185 - Javacard 2.x source code
// 
// --------------------------------------------------------------------------- 
// This implementation: © Copyright Australian Government
// PLAID: © Copyright Australian Government
// 
// A copy of the entire Licence is available upon email request from 
// plaid@humanservices.gov.au or by download from https://www.plaid.gov.au 
// 
// Subject to the terms of the Licence, the Australian Government grants to 
// the User a perpetual, irrevocable, world-wide, non-exclusive, royalty free and 
// no-charge licence to use, reproduce, adapt, modify, enhance, communicate, 
// sub-license and distribute PLAID and/or its source code. Clause 2.1 includes 
// the right to incorporate PLAID into any Product developed by the User.
// 
// By using PLAID and/or its source code you agree to be bound by the Licence.
// 
// ---------------------------------------------------------------------------
// Status: Prototype 0.804
// Issue Date: October 2011
// 
// Author: Glenn Mitchell (Australian Government)
// 
// Incorporating suggestions by Petr Novak (HID Global)
// 

package plaid804;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*; 

/**
 * <b>Class: PLAID</b><p>
 * <b>Generic Description</b><p>
 * This javacard applet implements PLAID authentication and the associated 
 * management routines as specified in Australian Standard AS 5185.<p>
 * <b>Design Considerations</b><p>
 * The following has been implemented in this reference model: <ul>
 * <li> There are 8 keypairs (RSA(IA) and AES(FA)) instantiated. This amount is
 * mandated by TOTAL_KEY_SETS.
 * <li> The variable "keyData" manages the correlation between the keySetID
 * values and the corresponding index position.
 * <li> The Shillkeys (decoy keys) are stored in their own cipher objects.
 * <li> The Shillkeys are generated/emulated in the constructor.
 * <li> PLAID authentication in Admin mode (using keysetID 0x0000) can only be 
 * performed through the contact interface (unless the contactInterface method
 * is modified to always return true).
 * <li> Before the applet is secured, the body of a "set data" command is DER
 * encoded.
 * <li> After the applet is secured, the body of a "set data" command is DER
 * encoded and then encrypted using AES.
 * <li> The method "processGetData" is blank in this reference implementation
 * as no additional user fields have been specified.
 */

public class PLAID804 extends Applet
{
  //CLA constants
  static final byte CLA_PROPRIETARY_CMD       =(byte)0x80;
    
  //INS constants  
  static final byte INS_INITIAL_AUTHENTICATE  =(byte)0x8A;
  static final byte INS_FINAL_AUTHENTICATE    =(byte)0x8C;
  static final byte INS_SET_DATA              =(byte)0xDB;
  static final byte INS_GET_DATA              =(byte)0xCB;

  //TAG constants
  static final byte DIVERSIFICATION_DATA      =(byte)0x01;
  static final byte ACS_RECORD                =(byte)0x02;
  static final byte PIN                       =(byte)0x03;
  static final byte SECURE_ICC                =(byte)0x04;
  static final byte MINUTIAE                  =(byte)0x06;
  static final byte IA_KEY                    =(byte)0x07;
  static final byte FA_KEY                    =(byte)0x08;
  static final byte REINITIALISE_CARD         =(byte)0x0A;
    
  //Opmode consts
  static final short OPMODE_1FACTOR           = 0x0000;
  static final short OPMODE_2FACTOR_PIN       = 0x0001;
  static final short OPMODE_2FACTOR_MINUTIAE  = 0x0002;
  
  //State constants 
  static final byte STATE_IDLE                =(byte)0x00;
  static final byte STATE_IA_COMPLETED        =(byte)0x01;
  static final byte STATE_FA_COMPLETED        =(byte)0x02;
  static final byte STATE_INITIAL             =(byte)0x00;
  static final byte STATE_SECURED             =(byte)0x01;
    
  //Offset constants - persistant (cardData)
  static final short OFFSET_VERSION               =(short)0;
  static final short OFFSET_SECURITY_STATE        =(short)1;
  static final short OFFSET_DIVERSIFICATION_DATA  =(short)2;
  static final short OFFSET_ACS_RECORD            =(short)10;
  static final short OFFSET_PIN_HASH              =(short)18;
  static final short OFFSET_MINUTIAE              =(short)38;
  
  //Length constants
  static final short LENGTH_VERSION               =(short)1;  
  static final short LENGTH_DIVERSIFICATION_DATA  =(short)8;
  static final short LENGTH_ACS_RECORD            =(short)8;
  static final short LENGTH_KEYSETID              =(short)2;
  static final short LENGTH_OPMODEID              =(short)2;
  static final short LENGTH_PIN                   =(short)8;
  static final short LENGTH_PIN_HASH              =(short)20;
  static final short LENGTH_PIN_HASH_EXTENDED     =(short)32;
  static final short LENGTH_MINUTIAE              =(short)224;
  static final short LENGTH_BUFFER128             =(short)128;
  static final short LENGTH_BUFFER16              =(short)16;
  static final short LENGTH_RND                   =(short)16;
  static final short LENGTH_CURRENT_SESSION       =(short)3;
  static final short LENGTH_CARDDATA              =(short)268; 
  static final short LENGTH_PUBLIC_EXPONENT       =(short)3;
  static final short LENGTH_FA_RESP_1F            =(short)16;
  static final short LENGTH_FA_RESP_2F_PIN        =(short)48;
  static final short LENGTH_FA_RESP_2F_MINUTIAE   =(short)240;
  static final short LENGTH_RSA1024               =(short)128;  

  //Offset constants - transient (currentSession)
  static final short OFFSET_CURRENT_STATE         = (short)0;
  static final short OFFSET_KEYSETID              = (short)1;

  //Misc
  static final byte[] PUBLIC_EXPONENT      = {0x01,0x00,0x01};
  static final byte[] ADMIN_KEYSETID       = {0x00,0x00};
  static final short ADMIN_KEYSET_SHORT    = (short)0;
  static final short TOTAL_KEY_SETS        = (short)8;
  static final byte OCTET_STRING_ASN1      = (byte)0x04;
  static final byte SEQUENCE_ASN1          = (byte)0x10;
  static final byte EXTENDED_LENGTH_ASN1   = (byte)0x80;
  static final byte NULL_VALUE             = (byte)0x00;
  static final byte PLAID_VERSION          = (byte)0x83;
  static final short FIRST_ASN1_VALUE      = (short)1;
  static final short SECOND_ASN1_VALUE     = (short)2;
  static final short THIRD_ASN1_VALUE      = (short)3;

  //Persistant objects
  private final byte[] cardData          = new byte[LENGTH_CARDDATA];
  private final byte[] keyData           = new byte[TOTAL_KEY_SETS*2];
  private final RSAPublicKey[] IAKey     = new RSAPublicKey[TOTAL_KEY_SETS];
  private final AESKey[] FAKey           = new AESKey[TOTAL_KEY_SETS];
  private final RSAPublicKey IAShillKey;
  private final AESKey FAShillKey;
  private final Cipher AESCipher;
  private final Cipher RSACipher;
  private final MessageDigest SHA1;
  private final RandomData rnd;

  //Transient objects
  private final byte[] currentSession;
  private final byte[] Buffer128, Buffer16; 
  private final AESKey sessionKey;

  /**
  * <b>Description</b><p>
  * This method invokes the variables required for the PLAID applet.<p>
  * <b>Design Considerations</b><p>
  * The Shillkeys are set during applet instantiation.
  * The padding mode used for the RSA object is PKCS#1.5. OAEP padding can
  * be supported however this approach has a significant performance hit
  * and may not be more secure for a protocol that does not expose the
  * RSA modulus.
  */
  private PLAID804() 
  { 
    Buffer128=JCSystem.makeTransientByteArray(LENGTH_BUFFER128, 
      JCSystem.CLEAR_ON_DESELECT);
    Buffer16=JCSystem.makeTransientByteArray(LENGTH_BUFFER16,
      JCSystem.CLEAR_ON_DESELECT);
    sessionKey=(AESKey)KeyBuilder.buildKey(
      KeyBuilder.TYPE_AES_TRANSIENT_RESET,KeyBuilder.LENGTH_AES_128,false);
    Util.arrayFillNonAtomic(cardData,(short)0,LENGTH_CARDDATA,NULL_VALUE);
    Util.arrayFillNonAtomic(keyData,(short)0,(short)(TOTAL_KEY_SETS*2),
      NULL_VALUE);
    currentSession=JCSystem.makeTransientByteArray(LENGTH_CURRENT_SESSION,
      JCSystem.CLEAR_ON_RESET);
    rnd=RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);  
    AESCipher=Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,false);
    RSACipher=Cipher.getInstance(Cipher.ALG_RSA_PKCS1,false);
    SHA1 = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
    for (short Index=0;Index<TOTAL_KEY_SETS;Index++)
    {
      IAKey[Index]=(RSAPublicKey)KeyBuilder.buildKey(
        KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_1024,false);
      IAKey[Index].setExponent(PUBLIC_EXPONENT,(short)0,LENGTH_PUBLIC_EXPONENT);
      FAKey[Index]=(AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, 
        KeyBuilder.LENGTH_AES_128,false);
    }
    IAShillKey=(RSAPublicKey)KeyBuilder.buildKey(
      KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_1024,false);
    IAShillKey.setExponent(PUBLIC_EXPONENT,(short)0,LENGTH_PUBLIC_EXPONENT);
    Buffer128[0] = (byte)0x80; 
    rnd.generateData(Buffer128,(short)1,(short)(LENGTH_RSA1024-2));
    Buffer128[(short)(LENGTH_RSA1024-1)] = (byte)0x01;
    IAShillKey.setModulus(Buffer128,(short)0,LENGTH_RSA1024);
    rnd.generateData(Buffer16,(short)0,LENGTH_RND);
    FAShillKey=(AESKey) KeyBuilder.buildKey(
      KeyBuilder.TYPE_AES,KeyBuilder.LENGTH_AES_128,false);
    FAShillKey.setKey(Buffer16,(short)0);
  }
  
  /**
  * <b>Description</b><p>
  * This method registers this applet instance with ICC's JCRE.
  */
    public static void install(byte[] params, short offset, byte length) 
    throws ISOException
  {
    (new PLAID804()).register(params,(short)(offset+1),params[offset]);
  }
  
  /**
  * <b>Return Type:</b> boolean<p
  * <b>Generic Description</b><p>
  * This method returns true iff the currently active communication channel
  * is through a contact interface as determined by the protocol byte.
  *
  * Note: Personalisation and administration authentication through 14443 can 
  * be achieved by modifying this function to always return true.
  */
  private static boolean contactInterface(APDU apdu)
  {
    return ((apdu.getProtocol()&APDU.PROTOCOL_MEDIA_MASK)==
      APDU.PROTOCOL_MEDIA_DEFAULT);
    //return true;  
  }

  /**
  * <b>Return Type:</b> byte[]<p>
  * <b>Generic Description</b><p>
  * This method parses the DER encoded ASN1 in to a format and returns
  * the index of the requested object.
  */
  private short getASN1Value(byte[] Buffer, short tagNo)
  {
    short indexASN1 = 0;
    short tagCount = 0;
    short traverse = 0;
    if (Buffer[indexASN1++] != SEQUENCE_ASN1) 
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    if ((Buffer[++indexASN1]&EXTENDED_LENGTH_ASN1)!=NULL_VALUE) 
      indexASN1++;
    while (true)
    {
      if (Buffer[indexASN1++] != OCTET_STRING_ASN1) 
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      if ((Buffer[indexASN1]&EXTENDED_LENGTH_ASN1)==NULL_VALUE)
        traverse = Util.makeShort(NULL_VALUE,Buffer[indexASN1++]); 
      else
      {
        indexASN1++;
        traverse = Util.makeShort(NULL_VALUE,Buffer[indexASN1++]); 
      }
      tagCount++;
      if (tagCount == tagNo)
        break;
      indexASN1+=traverse;
    }
    return indexASN1;
  }  
    
  /**
  * <b>Description</b><p>
  * This method determines the nature of the APDU as determined by the
  * instruction byte and invokes the corresponding method. 
  *
  * <b>Description - case INS_INITIAL_AUTHENTICATE</b><p>
  * This method performs the ICC side of Initial Authenticate command as
  * specified in Australian Standard AS-5185<p>
  * <b>Design Considerations</b><p>
  * 1 - The ICC will allow allow authentication in administration mode through
  * the contact interface.<p>
  * 2 - After selecting an RSA key to use, the ICC will continue to "search"
  * through the list of remaining keys to avoid potential timing attacks.<p>
  * 3 - If no appropriate key is found, the ICC will use the Shillkey.<p>
  
  * <b>Description - case INS_FINAL_AUTHENTICATE</b><p>
  * This method performs the ICC side of Final Authenticate command as
  * specified in Australian Standard AS-5185<p>
  * <b>Design Considerations</b><p>
  * 1 - In the case where the opmodeID cannot be determined, the ICC
  * responds as if opmodeID was 1-factor. 
  *
  * <b>Description - case INS_SET_DATA</b><p>
  * This method manages the setting of PLAID variables.<p>
  * <b>Design Considerations</b><p>
  * Before a card is secured, variables may be set by storing the value in
  * the body of an APDU in a DER format. Once a card is secured, data can 
  * only be set by completing PLAID authentication in administrator mode and 
  * encrypting the DER encoded body of the APDU with the session key.
  * The setting of the keys requires placement in next available space as 
  * indicated by the array "keyData". 
  */
  
  public void process(APDU apdu)
  {
    if (selectingApplet())
      return;
    byte[] APDUBuffer=apdu.getBuffer();  
    short Length = apdu.setIncomingAndReceive();
    short Location = 0;
    short currentKey = 0;
    switch (APDUBuffer[ISO7816.OFFSET_INS])
    {
      case INS_INITIAL_AUTHENTICATE: 
        if (cardData[OFFSET_SECURITY_STATE] != STATE_SECURED)
          ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        short APDUIndex = 9;
        Util.arrayCopyNonAtomic(keyData,(short)0,Buffer16,(short)0,
          LENGTH_BUFFER16);
        while (APDUBuffer[(short)(APDUIndex-1)] == LENGTH_KEYSETID)
        {
          currentKey = Util.makeShort(APDUBuffer[APDUIndex],
            APDUBuffer[(short)(APDUIndex+1)]);
          for (short i=0;i<(TOTAL_KEY_SETS*2);i+=LENGTH_KEYSETID)
          {
            if ((currentSession[OFFSET_CURRENT_STATE]!=STATE_IA_COMPLETED)&&
              (currentKey==Util.getShort(Buffer16,i)))
            {
              RSACipher.init(IAKey[Location],Cipher.MODE_ENCRYPT);  
              AESCipher.init(FAKey[Location],Cipher.MODE_DECRYPT);
              currentSession[OFFSET_CURRENT_STATE] = STATE_IA_COMPLETED;
              Util.arrayCopyNonAtomic(Buffer16,(short)(Location*2),Buffer128,
                (short)0,LENGTH_KEYSETID);
              Util.arrayCopyNonAtomic(APDUBuffer,APDUIndex,currentSession,
                OFFSET_KEYSETID,LENGTH_KEYSETID);
              if ((currentKey == ADMIN_KEYSET_SHORT) && (!contactInterface(apdu)))
              {
                currentSession[OFFSET_CURRENT_STATE] = STATE_IDLE;
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
              }
            }
            Location++;
          }
          Location = 0;
          APDUIndex+=4;
        }
        if (currentSession[OFFSET_CURRENT_STATE] != STATE_IA_COMPLETED)
        {
          RSACipher.init(IAShillKey,Cipher.MODE_ENCRYPT);
          AESCipher.init(FAShillKey,Cipher.MODE_DECRYPT);
          currentSession[OFFSET_CURRENT_STATE] = STATE_IDLE;
          Util.arrayCopyNonAtomic(Buffer16,(short)0,Buffer128,(short)0,
            LENGTH_KEYSETID);
          Util.arrayCopyNonAtomic(APDUBuffer,APDUIndex,currentSession,
            OFFSET_KEYSETID,LENGTH_KEYSETID);
        }
        Util.arrayCopyNonAtomic(cardData,OFFSET_DIVERSIFICATION_DATA,Buffer128,
          LENGTH_KEYSETID,LENGTH_DIVERSIFICATION_DATA);
        rnd.generateData(Buffer128,(short)(LENGTH_KEYSETID+
          LENGTH_DIVERSIFICATION_DATA),LENGTH_RND);
        Util.arrayCopyNonAtomic(Buffer128,(short)(LENGTH_KEYSETID+
          LENGTH_DIVERSIFICATION_DATA),Buffer128,(short)(LENGTH_KEYSETID+
          LENGTH_DIVERSIFICATION_DATA+LENGTH_RND),LENGTH_RND); 
        RSACipher.doFinal(Buffer128,(short)0,(short)(LENGTH_KEYSETID+
          LENGTH_DIVERSIFICATION_DATA+LENGTH_RND+LENGTH_RND),
          APDUBuffer,(short)0);
        apdu.setOutgoingAndSend((short)0,LENGTH_RSA1024);
        return;  
      case INS_FINAL_AUTHENTICATE:
        if (currentSession[OFFSET_CURRENT_STATE] != STATE_IA_COMPLETED)
          ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        AESCipher.doFinal(APDUBuffer,ISO7816.OFFSET_CDATA,Length,
          APDUBuffer,(short)0);
        Util.arrayCopyNonAtomic(APDUBuffer,LENGTH_OPMODEID,Buffer128,(short)
          (LENGTH_KEYSETID+LENGTH_DIVERSIFICATION_DATA+LENGTH_RND),(short)
          (LENGTH_RND+LENGTH_RND));
        SHA1.doFinal(Buffer128,(short)(LENGTH_KEYSETID+
          LENGTH_DIVERSIFICATION_DATA),(short)(LENGTH_RND+LENGTH_RND),Buffer128,
          (short)(LENGTH_KEYSETID+LENGTH_DIVERSIFICATION_DATA+(3*LENGTH_RND)));
        byte[] source;
        if ((Util.arrayCompare(Buffer128,(short)(LENGTH_KEYSETID+
          LENGTH_DIVERSIFICATION_DATA+LENGTH_RND+LENGTH_RND),Buffer128,
          (short)(LENGTH_KEYSETID+LENGTH_DIVERSIFICATION_DATA+(3*LENGTH_RND)),
          LENGTH_BUFFER16)==0)&&(currentSession[OFFSET_CURRENT_STATE]
          == STATE_IA_COMPLETED))
        {
          sessionKey.setKey(APDUBuffer,(short)(LENGTH_OPMODEID+LENGTH_BUFFER16));
          AESCipher.init(sessionKey,Cipher.MODE_ENCRYPT);
          source = cardData;
          currentSession[OFFSET_CURRENT_STATE] = STATE_FA_COMPLETED;
        }
        else
        {
          sessionKey.setKey(Buffer16,(short)0);
          AESCipher.init(FAShillKey,Cipher.MODE_ENCRYPT);    
          source = Buffer128;
          currentSession[OFFSET_CURRENT_STATE] = STATE_IDLE;
          
        }
        switch (Util.getShort(APDUBuffer,(short)0))
        {
          case OPMODE_1FACTOR: 
            Location = AESCipher.doFinal(source,OFFSET_DIVERSIFICATION_DATA, 
              (short)(LENGTH_DIVERSIFICATION_DATA+LENGTH_ACS_RECORD), 
              APDUBuffer, Location); 
            break; 
          case OPMODE_2FACTOR_PIN: 
            Location = AESCipher.doFinal(source,OFFSET_DIVERSIFICATION_DATA,
              (short)(LENGTH_DIVERSIFICATION_DATA+LENGTH_ACS_RECORD+
              LENGTH_PIN_HASH_EXTENDED), APDUBuffer, Location); 
            break; 
          case OPMODE_2FACTOR_MINUTIAE: 
            Location = AESCipher.update(source,OFFSET_DIVERSIFICATION_DATA, 
              (short)(LENGTH_DIVERSIFICATION_DATA+LENGTH_ACS_RECORD), 
              APDUBuffer, Location); 
            Location += AESCipher.doFinal(source,OFFSET_MINUTIAE,
              LENGTH_MINUTIAE, APDUBuffer, Location); 
            break; 
          default: 
            Location = AESCipher.doFinal(source,OFFSET_DIVERSIFICATION_DATA,
              (short)(LENGTH_DIVERSIFICATION_DATA+LENGTH_ACS_RECORD),
              APDUBuffer, Location); 
            break; 
        } 
        apdu.setOutgoingAndSend((short)0,Location); 
        return; 
      case INS_SET_DATA: 
        boolean adminKeyset;
        if ((currentSession[OFFSET_CURRENT_STATE]==STATE_FA_COMPLETED)&&
          (Util.arrayCompare(currentSession,OFFSET_KEYSETID,ADMIN_KEYSETID,
          (short)0,LENGTH_KEYSETID)==0))
        {
          try
          {
            AESCipher.init(sessionKey,Cipher.MODE_DECRYPT);
            AESCipher.doFinal(APDUBuffer,ISO7816.OFFSET_CDATA,(short)Length,
            APDUBuffer,(short)0);
          }
          catch (CryptoException ex)
          {
            ISOException.throwIt(ex.getReason());
          }
        }
        else if (cardData[OFFSET_SECURITY_STATE]==STATE_INITIAL)
          Util.arrayCopyNonAtomic(APDUBuffer,ISO7816.OFFSET_CDATA,APDUBuffer,
            (short)0,Length);
        else 
          ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        switch (APDUBuffer[getASN1Value(APDUBuffer,FIRST_ASN1_VALUE)])
        {
          case DIVERSIFICATION_DATA:
            Util.arrayCopy(APDUBuffer,getASN1Value(APDUBuffer,
            SECOND_ASN1_VALUE),cardData,OFFSET_DIVERSIFICATION_DATA,
            LENGTH_DIVERSIFICATION_DATA);
            return;
          case ACS_RECORD:
            Util.arrayCopy(APDUBuffer,getASN1Value(APDUBuffer,
              SECOND_ASN1_VALUE),cardData,OFFSET_ACS_RECORD,LENGTH_ACS_RECORD);
            return;
          case MINUTIAE:
            Util.arrayCopy(APDUBuffer,getASN1Value(APDUBuffer,
              SECOND_ASN1_VALUE),cardData,OFFSET_MINUTIAE,LENGTH_MINUTIAE);
            return;
          case PIN:
            SHA1.reset();
            SHA1.doFinal(APDUBuffer,getASN1Value(APDUBuffer,SECOND_ASN1_VALUE),
              LENGTH_PIN,cardData,OFFSET_PIN_HASH);
            return;
          case SECURE_ICC:
            cardData[OFFSET_SECURITY_STATE] = STATE_SECURED;
            return;
          case REINITIALISE_CARD:
            Util.arrayFillNonAtomic(cardData,(short)0,LENGTH_CARDDATA,
              NULL_VALUE);
            Util.arrayFillNonAtomic(keyData,(short)0,(short)(TOTAL_KEY_SETS*2),
              NULL_VALUE);
            return;
          case IA_KEY:
            Location = getASN1Value(APDUBuffer,SECOND_ASN1_VALUE);
            adminKeyset = (Util.arrayCompare(APDUBuffer,Location,
              ADMIN_KEYSETID,(short)0,LENGTH_KEYSETID)==0);
            for (short i=2;i<(TOTAL_KEY_SETS*2);i+=2)
            {
              if ((Util.arrayCompare(keyData,i,APDUBuffer,Location,
                LENGTH_KEYSETID) == 0)||((keyData[i]==NULL_VALUE)&&
                (keyData[(short)(i+1)]==NULL_VALUE))||(adminKeyset))
              {
                Util.arrayCopy(APDUBuffer,Location,keyData,(short)(i),
                  LENGTH_KEYSETID);
                Location = getASN1Value(APDUBuffer,THIRD_ASN1_VALUE);     
                if (adminKeyset)
                  currentKey=0;
                else
                  currentKey=(short)(i/2);
                IAKey[currentKey].setModulus(APDUBuffer,Location,
                  LENGTH_RSA1024); 
                return;
              }  
            }
          case FA_KEY:
            Location = getASN1Value(APDUBuffer,SECOND_ASN1_VALUE);
            adminKeyset = (Util.arrayCompare(APDUBuffer,Location,
              ADMIN_KEYSETID,(short)0,LENGTH_KEYSETID)==0);
            for (short i=2;i<(TOTAL_KEY_SETS*2);i+=2)
            {
              if ((Util.arrayCompare(keyData,i,APDUBuffer,Location,
                LENGTH_KEYSETID) == 0)||(adminKeyset))
              {
                Location = getASN1Value(APDUBuffer,THIRD_ASN1_VALUE);        
                if (adminKeyset)
                  currentKey=0;
                else
                  currentKey=(short)(i/2);
                FAKey[currentKey].setKey(APDUBuffer,Location); 
                return;
              }
            }
          default: 
              ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
      default: 
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }
}