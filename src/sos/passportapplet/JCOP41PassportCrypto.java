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
 * $Id: FileSystem.java 143 2006-08-03 15:52:19Z ceesb $
 */

package sos.passportapplet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/***
 * Class that implements creation signatures of ALG_DES_MAC8_ISO9797_M2_ALG3 
 * using ALG_DES_MAC8_ISO9797_M2.
 * 
 * @author ceesb
 *
 */public class JCOP41PassportCrypto extends PassportCrypto {
    private Cipher macCiphECB;
    private byte[] tempSpace_verifyMac;

    JCOP41PassportCrypto(KeyStore keyStore) {
        super(keyStore);
                
        tempSpace_verifyMac = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_RESET);
    }
    
    protected void init() {
        ciph = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        
        sig = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2,
                                    false);
        
        macCiphECB = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);

    }
 
    public void initMac(byte mode) {
        DESKey k = keyStore.getMacKey(KeyStore.KEY_A);
        
        sig.init(k, Signature.MODE_SIGN);    
    }
        
    public void createMacFinal(byte[] msg, short msg_offset, short msg_len,
            byte[] mac, short mac_offset) {
        DESKey kA = keyStore.getMacKey(KeyStore.KEY_A);
        DESKey kB = keyStore.getMacKey(KeyStore.KEY_B);

        updateMac(msg, msg_offset, msg_len);
        sig.sign(null, (short)0, (short)0, mac, mac_offset);
        
        macCiphECB.init(kB, Cipher.MODE_DECRYPT);
        macCiphECB.doFinal(mac, mac_offset, (short)8, mac, mac_offset);
        
        macCiphECB.init(kA, Cipher.MODE_ENCRYPT);
        macCiphECB.doFinal(mac, mac_offset, (short)8, mac, mac_offset);
    }

    
    public boolean verifyMacFinal(byte[] msg, short msg_offset, short msg_len,
            byte[] mac, short mac_offset) {
      
        createMacFinal(msg, msg_offset, msg_len, tempSpace_verifyMac, (short)0);
               
        if(Util.arrayCompare(mac, mac_offset, tempSpace_verifyMac, (short)0, (short)8) == 0) {
            return true;
        }
        return false;
    }
}
