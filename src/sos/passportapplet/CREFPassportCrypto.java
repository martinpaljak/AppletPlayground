/*
 * passportapplet - A reference implementation of the MRTD standards.
 *
 * Copyright (C) 2006  SoS group, Radboud University
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: CREFPassportCrypto.java 945 2009-05-12 08:31:57Z woj76 $
 */

package sos.passportapplet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * This class is a hack. It (probably) implements 
 * => encrypt/decrypt of ALG_DES_CBC_NOPAD using ALG_DES_CBC_ISO9797_M2

 * This is because ALG_DES_CBC_NOPAD and ALG_DES_MAC8_ISO9797_1_M2_ALG3 do not 
 * exist on CREF.
 * 
 * @author Cees-Bart Breunesse <ceesb@cs.ru.nl>
 * @author Ronny Wichers Schreur <ronny@cs.ru.nl>
 * 
 * @version $Revision: 945 $
 */
public class CREFPassportCrypto extends JCOP41PassportCrypto implements ISO7816 {
    private byte padding;

    protected void init() {
        ciph = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);        

        sig = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2,
                                    false);
    }
    
    CREFPassportCrypto(KeyStore keyStore) {
        super(keyStore);

        tempSpace_decryptDES = JCSystem.makeTransientByteArray((short) 16,
                                                               JCSystem.CLEAR_ON_RESET);
        tempSpace_doMacFinal = JCSystem.makeTransientByteArray((short) 24,
                                                               JCSystem.CLEAR_ON_RESET);
    }
    
    private short decryptDESusingDESCBCM2(DESKey key, byte[] in,
            short in_offset, byte[] out, short out_offset, short length) {
        if ((ciph.getAlgorithm() != Cipher.ALG_DES_CBC_ISO9797_M2)
                || ((short) (length + out_offset + 16) > (short) (out.length))
                || ((short) (length + in_offset) > (short) in.length))
            ISOException.throwIt((short) 0x6d69);

        ciph.init(key, Cipher.MODE_ENCRYPT);
        ciph.doFinal(ZERO,
                     (short) 0,
                     (short) 8,
                     tempSpace_decryptDES,
                     (short) 0);

        ciph.init(key, Cipher.MODE_DECRYPT);
        short written = ciph.update(in, in_offset, length, out, out_offset);
        written += ciph.doFinal(tempSpace_decryptDES,
                         (short) 0,
                         (short) (16),
                         out,
                         (short) (out_offset + written));
        
        return (short)(written - 8); // FIXME: hack, compensate for padding
    }

    private static byte[] tempSpace_decryptDES;
    private static final byte[] ZERO = { 0, 0, 0, 0, 0, 0, 0, 0 };
    private DESKey k;
    private byte[] tempSpace_doMacFinal;
    
    private void decryptInit(DESKey k) {
        this.k = k;
    }
    
    private void encryptInit(DESKey k) {
        this.k = k;
    }

    public void decryptInit() {
        k=keyStore.getCryptKey();
    }
    
    public short decrypt(byte[] ctext, short ctext_offset, short ctext_len,
                         byte[] ptext, short ptext_offset) {
        CryptoException.throwIt((short)0x6d66);
        return 0;
    }
    
    public short encrypt(byte[] ctext, short ctext_offset, short ctext_len,
            byte[] ptext, short ptext_offset) {
        CryptoException.throwIt((short)0x6d66);
        return 0;
    }  

    public short decryptFinal(byte[] ctext, short ctext_offset, short ctext_len,
            byte[] ptext, short ptext_offset) {        
        return decryptDESusingDESCBCM2(k, ctext, ctext_offset, ptext, ptext_offset, ctext_len);
    }

    public short encryptInit(byte padding, byte[] plainText, short plaintextOffset, short plaintextLength) {
        return encryptInit(keyStore.getCryptKey(), padding, plainText, plaintextOffset, plaintextLength);

    }
    
    private short encryptInit(DESKey k, byte padding, byte[] plainText, short plaintextOffset, short plaintextLength) {
        this.k = k;
        this.padding = padding;
        return plaintextLength;
    }
        
    public short encryptFinal(byte[] ptext,  short ptext_offset, short ptext_len,
            byte[] ctext, short ctext_offset) {
        
        ciph.init(k, Cipher.MODE_ENCRYPT);
        short len = ciph.doFinal(ptext, ptext_offset, ptext_len, ctext, ctext_offset);

        if(padding == PAD_INPUT) {
            // ALG_DES_CBC_ISO9797_M2 does padding
            return len;
        }
        else if (padding == DONT_PAD_INPUT) {
            return (short)(len - 8); // FIXME: hack
        }
        return 0;
    }
        
    public void createMacFinal(byte[] msg, short msg_offset, short msg_len,
            byte[] mac, short mac_offset) {
        DESKey kA = keyStore.getMacKey(KeyStore.KEY_A);
        DESKey kB = keyStore.getMacKey(KeyStore.KEY_B);

//        updateMac(msg, msg_offset, msg_len);
        sig.sign(msg, msg_offset, msg_len, mac, mac_offset);
        
        decryptInit(kB);
        short tempmac_offset = 0;
        //macCiphECB.init(kB, Cipher.MODE_DECRYPT);
        decryptFinal(mac, mac_offset, (short)8, tempSpace_doMacFinal, tempmac_offset );
        //macCiphECB.doFinal(mac, mac_offset, (short)8, mac, mac_offset);
        
        encryptInit(kA);
        //macCiphECB.init(kA, Cipher.MODE_ENCRYPT);
        encryptFinal(tempSpace_doMacFinal, tempmac_offset, (short)8, tempSpace_doMacFinal, tempmac_offset);
        //macCiphECB.doFinal(mac, mac_offset, (short)8, mac, mac_offset);
        
        Util.arrayCopyNonAtomic(tempSpace_doMacFinal, tempmac_offset, mac, mac_offset, (short)8);
    }

}
