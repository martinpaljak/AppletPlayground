    

package com.btchip.applet.poc;

import javacard.framework.JCSystem;
import javacard.framework.Util;







    


    


    


    


    

   
    


    


    

    
    


    








    


    








    





    
 
public class Ripemd160 {
    
    public static void init() {
        scratch = JCSystem.makeTransientByteArray((short)BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }
                                
    public static void hash32(byte[] buffer, short offset, byte[] target, short targetOffset)
    {
      byte i;
      short H0 ## HIGH = (short)0, H0 ## LOW = (short)0; short H1 ## HIGH = (short)0, H1 ## LOW = (short)0; short H2 ## HIGH = (short)0, H2 ## LOW = (short)0; short H3 ## HIGH = (short)0, H3 ## LOW = (short)0; short H4 ## HIGH = (short)0, H4 ## LOW = (short)0;
      short X0 ## HIGH = (short)0, X0 ## LOW = (short)0; short X1 ## HIGH = (short)0, X1 ## LOW = (short)0; short X2 ## HIGH = (short)0, X2 ## LOW = (short)0; short X3 ## HIGH = (short)0, X3 ## LOW = (short)0; short X4 ## HIGH = (short)0, X4 ## LOW = (short)0; short X5 ## HIGH = (short)0, X5 ## LOW = (short)0; short X6 ## HIGH = (short)0, X6 ## LOW = (short)0; short X7 ## HIGH = (short)0, X7 ## LOW = (short)0; short X8 ## HIGH = (short)0, X8 ## LOW = (short)0; short X9 ## HIGH = (short)0, X9 ## LOW = (short)0; short X10 ## HIGH = (short)0, X10 ## LOW = (short)0; short X11 ## HIGH = (short)0, X11 ## LOW = (short)0; short X12 ## HIGH = (short)0, X12 ## LOW = (short)0; short X13 ## HIGH = (short)0, X13 ## LOW = (short)0; short X14 ## HIGH = (short)0, X14 ## LOW = (short)0; short X15 ## HIGH = (short)0, X15 ## LOW = (short)0;
      short X ## HIGH = (short)0, X ## LOW = (short)0;
      short A ## HIGH = (short)0, A ## LOW = (short)0; short B ## HIGH = (short)0, B ## LOW = (short)0; short C ## HIGH = (short)0, C ## LOW = (short)0; short D ## HIGH = (short)0, D ## LOW = (short)0; short E ## HIGH = (short)0, E ## LOW = (short)0; short Ap ## HIGH = (short)0, Ap ## LOW = (short)0; short Bp ## HIGH = (short)0, Bp ## LOW = (short)0; short Cp ## HIGH = (short)0, Cp ## LOW = (short)0; short Dp ## HIGH = (short)0, Dp ## LOW = (short)0; short Ep ## HIGH = (short)0, Ep ## LOW = (short)0; short T ## HIGH = (short)0, T ## LOW = (short)0; short s ## HIGH = (short)0, s ## LOW = (short)0; short tmp ## HIGH = (short)0, tmp ## LOW = (short)0;
      short addX, addY, addLow, addCarry; short rotH, rotL, rotMsk, rotSl, rotSh;
      H0 ## HIGH = (short) 0x6745; H0 ## LOW = (short) 0x2301;
      H1 ## HIGH = (short) 0xEFCD; H1 ## LOW = (short) 0xAB89;
      H2 ## HIGH = (short) 0x98BA; H2 ## LOW = (short) 0xDCFE;
      H3 ## HIGH = (short) 0x1032; H3 ## LOW = (short) 0x5476;
      H4 ## HIGH = (short) 0xC3D2; H4 ## LOW = (short) 0xE1F0;
      Util.arrayCopyNonAtomic(buffer, offset, scratch, (short)0, (short)32);
      scratch[32] = (byte)0x80;
      scratch[64 - 7] = (byte)0x01;
      // encode 64 bytes from input block into an array of 16 unsigned integers
      for (i = 0; i < 16; i++) {
        short low = (short)((scratch[offset++] & 0xff) | ((scratch[offset++] & 0xff) << 8));
        short high = (short)((scratch[offset++] & 0xff) | ((scratch[offset++] & 0xff) << 8));
        switch(i) {
            case 0: X0 ## HIGH = (short) high; X0 ## LOW = (short) low; break;
            case 1: X1 ## HIGH = (short) high; X1 ## LOW = (short) low; break;
            case 2: X2 ## HIGH = (short) high; X2 ## LOW = (short) low; break;
            case 3: X3 ## HIGH = (short) high; X3 ## LOW = (short) low; break;
            case 4: X4 ## HIGH = (short) high; X4 ## LOW = (short) low; break;
            case 5: X5 ## HIGH = (short) high; X5 ## LOW = (short) low; break;
            case 6: X6 ## HIGH = (short) high; X6 ## LOW = (short) low; break;
            case 7: X7 ## HIGH = (short) high; X7 ## LOW = (short) low; break;
            case 8: X8 ## HIGH = (short) high; X8 ## LOW = (short) low; break;
            case 9: X9 ## HIGH = (short) high; X9 ## LOW = (short) low; break;
            case 10: X10 ## HIGH = (short) high; X10 ## LOW = (short) low; break;
            case 11: X11 ## HIGH = (short) high; X11 ## LOW = (short) low; break;
            case 12: X12 ## HIGH = (short) high; X12 ## LOW = (short) low; break;
            case 13: X13 ## HIGH = (short) high; X13 ## LOW = (short) low; break;            
            case 14: X14 ## HIGH = (short) high; X14 ## LOW = (short) low; break;
            case 15: X15 ## HIGH = (short) high; X15 ## LOW = (short) low; break;            
        }
      }      
      A ## HIGH =  H0 ## HIGH; A ## LOW =  H0 ## LOW;
      Ap ## HIGH =  H0 ## HIGH; Ap ## LOW =  H0 ## LOW;
      B ## HIGH =  H1 ## HIGH; B ## LOW =  H1 ## LOW;
      Bp ## HIGH =  H1 ## HIGH; Bp ## LOW =  H1 ## LOW;
      C ## HIGH =  H2 ## HIGH; C ## LOW =  H2 ## LOW;
      Cp ## HIGH =  H2 ## HIGH; Cp ## LOW =  H2 ## LOW;
      D ## HIGH =  H3 ## HIGH; D ## LOW =  H3 ## LOW;
      Dp ## HIGH =  H3 ## HIGH; Dp ## LOW =  H3 ## LOW;
      E ## HIGH =  H4 ## HIGH; E ## LOW =  H4 ## LOW;
      Ep ## HIGH =  H4 ## HIGH; Ep ## LOW =  H4 ## LOW;                  
      for (i = 0; i < 80; i++) // rounds 0...15
        {
          s ## HIGH = (short) 0; s ## LOW = (short) S[i];          
          switch(i >> 4) {
              case 0:
                  //T = A + (B ^ C ^ D) + X[i];
                  T ## HIGH =  B ## HIGH; T ## LOW =  B ## LOW;
                  T ## HIGH ^=  C ## HIGH; T ## LOW ^=  C ## LOW;
                  T ## HIGH ^=  D ## HIGH; T ## LOW ^=  D ## LOW;
                  addX = T ## LOW; addY =  A ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  A ## HIGH;
                  switch(i) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = T ## LOW; addY =  X ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  X ## HIGH;                  
                  break;
              case 1:
                  T ## HIGH =  B ## HIGH; T ## LOW =  B ## LOW;
                  T ## HIGH &=  C ## HIGH; T ## LOW &=  C ## LOW;
                  tmp ## HIGH =  B ## HIGH; tmp ## LOW =  B ## LOW;
                  tmp ## HIGH = (short)(~tmp ## HIGH); tmp ## LOW = (short)(~tmp ## LOW);
                  tmp ## HIGH &=  D ## HIGH; tmp ## LOW &=  D ## LOW;
                  T ## HIGH |=  tmp ## HIGH; T ## LOW |=  tmp ## LOW;
                  addX = T ## LOW; addY =  A ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  A ## HIGH;
                  switch(R[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = T ## LOW; addY =  X ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  X ## HIGH;
                  addX = T ## LOW; addY =  (short)0x7999; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  (short)0x5A82;
                  //T = A + ((B & C) | (~B & D)) + X[R[i]] + 0x5A827999;
                  break;
              case 2:
                  T ## HIGH =  C ## HIGH; T ## LOW =  C ## LOW;
                  T ## HIGH = (short)(~T ## HIGH); T ## LOW = (short)(~T ## LOW);
                  T ## HIGH |=  B ## HIGH; T ## LOW |=  B ## LOW;
                  T ## HIGH ^=  D ## HIGH; T ## LOW ^=  D ## LOW;
                  addX = T ## LOW; addY =  A ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  A ## HIGH;
                  switch(R[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = T ## LOW; addY =  X ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  X ## HIGH;
                  addX = T ## LOW; addY =  (short)0xEBA1; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  (short)0x6ED9;
                  //T = A + ((B | ~C) ^ D) + X[R[i]] + 0x6ED9EBA1;
                  break;
              case 3:
                  T ## HIGH =  B ## HIGH; T ## LOW =  B ## LOW;
                  T ## HIGH &=  D ## HIGH; T ## LOW &=  D ## LOW;
                  tmp ## HIGH =  D ## HIGH; tmp ## LOW =  D ## LOW;
                  tmp ## HIGH = (short)(~tmp ## HIGH); tmp ## LOW = (short)(~tmp ## LOW);
                  tmp ## HIGH &=  C ## HIGH; tmp ## LOW &=  C ## LOW;
                  T ## HIGH |=  tmp ## HIGH; T ## LOW |=  tmp ## LOW;
                  addX = T ## LOW; addY =  A ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  A ## HIGH;
                  switch(R[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = T ## LOW; addY =  X ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  X ## HIGH;
                  addX = T ## LOW; addY =  (short)0xBCDC; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  (short)0x8F1B;
                  //T = A + ((B & D) | (C & ~D)) + X[R[i]] + 0x8F1BBCDC;
                  break;
              case 4:
                  T ## HIGH =  D ## HIGH; T ## LOW =  D ## LOW;
                  T ## HIGH = (short)(~T ## HIGH); T ## LOW = (short)(~T ## LOW);
                  T ## HIGH |=  C ## HIGH; T ## LOW |=  C ## LOW;
                  T ## HIGH ^=  B ## HIGH; T ## LOW ^=  B ## LOW;
                  addX = T ## LOW; addY =  A ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  A ## HIGH;
                  switch(R[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = T ## LOW; addY =  X ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  X ## HIGH;
                  addX = T ## LOW; addY =  (short)0xFD4E; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  (short)0xA953;
                  //T = A + (B ^ (C | ~D)) + X[R[i]] + 0xA953FD4E;
                  break;
          }
          A ## HIGH =  E ## HIGH; A ## LOW =  E ## LOW;
          E ## HIGH =  D ## HIGH; E ## LOW =  D ## LOW;
          D ## HIGH =  C ## HIGH; D ## LOW =  C ## LOW;
          rotMsk = mask[ (short)10]; rotH = D ## HIGH; rotL = D ## LOW; rotSh = (short) (rotMsk & ((short) (rotH >>> ((short)(16- (short)10))))); rotSl = (short) (rotMsk & ((short) (rotL >>> ((short)(16- (short)10))))); D ## HIGH = (short) ((rotH<<(short) (short)10) | rotSl); D ## LOW = (short) ((rotL<<(short) (short)10) | rotSh);
          C ## HIGH =  B ## HIGH; C ## LOW =  B ## LOW;
          B ## HIGH =  T ## HIGH; B ## LOW =  T ## LOW;
          rotMsk = mask[ sLOW]; rotH = B ## HIGH; rotL = B ## LOW; rotSh = (short) (rotMsk & ((short) (rotH >>> ((short)(16- sLOW))))); rotSl = (short) (rotMsk & ((short) (rotL >>> ((short)(16- sLOW))))); B ## HIGH = (short) ((rotH<<(short) sLOW) | rotSl); B ## LOW = (short) ((rotL<<(short) sLOW) | rotSh);
          addX = B ## LOW; addY =  A ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); B ## HIGH += addCarry; B ## LOW = addLow; B ## HIGH +=  A ## HIGH;
          






          s ## HIGH = (short) 0; s ## LOW = (short) Sp[i];
          switch(i >> 4) {
              case 0:
                  T ## HIGH =  Dp ## HIGH; T ## LOW =  Dp ## LOW;
                  T ## HIGH = (short)(~T ## HIGH); T ## LOW = (short)(~T ## LOW);
                  T ## HIGH |=  Cp ## HIGH; T ## LOW |=  Cp ## LOW;
                  T ## HIGH ^=  Bp ## HIGH; T ## LOW ^=  Bp ## LOW;
                  addX = T ## LOW; addY =  Ap ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  Ap ## HIGH;
                  switch(Rp[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = T ## LOW; addY =  X ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  X ## HIGH;
                  addX = T ## LOW; addY =  (short)0x8BE6; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  (short)0x50A2;
                  //T = Ap + (Bp ^ (Cp | ~Dp)) + X[Rp[i]] + 0x50A28BE6;
                  break;
              case 1:
                  T ## HIGH =  Bp ## HIGH; T ## LOW =  Bp ## LOW;
                  T ## HIGH &=  Dp ## HIGH; T ## LOW &=  Dp ## LOW;
                  tmp ## HIGH =  Dp ## HIGH; tmp ## LOW =  Dp ## LOW;
                  tmp ## HIGH = (short)(~tmp ## HIGH); tmp ## LOW = (short)(~tmp ## LOW);
                  tmp ## HIGH &=  Cp ## HIGH; tmp ## LOW &=  Cp ## LOW;
                  T ## HIGH |=  tmp ## HIGH; T ## LOW |=  tmp ## LOW;
                  addX = T ## LOW; addY =  Ap ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  Ap ## HIGH;
                  switch(Rp[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = T ## LOW; addY =  X ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  X ## HIGH;
                  addX = T ## LOW; addY =  (short)0xD124; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  (short)0x5C4D;
                  //T = Ap + ((Bp & Dp) | (Cp & ~Dp)) + X[Rp[i]] + 0x5C4DD124;
                  break;
              case 2:
                  T ## HIGH =  Cp ## HIGH; T ## LOW =  Cp ## LOW;
                  T ## HIGH = (short)(~T ## HIGH); T ## LOW = (short)(~T ## LOW);
                  T ## HIGH |=  Bp ## HIGH; T ## LOW |=  Bp ## LOW;
                  T ## HIGH ^=  Dp ## HIGH; T ## LOW ^=  Dp ## LOW;
                  addX = T ## LOW; addY =  Ap ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  Ap ## HIGH;
                  switch(Rp[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = T ## LOW; addY =  X ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  X ## HIGH;
                  addX = T ## LOW; addY =  (short)0x3EF3; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  (short)0x6D70;
                  //T = Ap + ((Bp | ~Cp) ^ Dp) + X[Rp[i]] + 0x6D703EF3;
                  break;
              case 3:
                  T ## HIGH =  Bp ## HIGH; T ## LOW =  Bp ## LOW;
                  T ## HIGH &=  Cp ## HIGH; T ## LOW &=  Cp ## LOW;
                  tmp ## HIGH =  Bp ## HIGH; tmp ## LOW =  Bp ## LOW;
                  tmp ## HIGH = (short)(~tmp ## HIGH); tmp ## LOW = (short)(~tmp ## LOW);
                  tmp ## HIGH &=  Dp ## HIGH; tmp ## LOW &=  Dp ## LOW;
                  T ## HIGH |=  tmp ## HIGH; T ## LOW |=  tmp ## LOW;
                  addX = T ## LOW; addY =  Ap ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  Ap ## HIGH;
                  switch(Rp[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = T ## LOW; addY =  X ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  X ## HIGH;
                  addX = T ## LOW; addY =  (short)0x76E9; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  (short)0x7A6D;
                  //T = Ap + ((Bp & Cp) | (~Bp & Dp)) + X[Rp[i]] + 0x7A6D76E9;
                  break;
              case 4:
                  T ## HIGH =  Bp ## HIGH; T ## LOW =  Bp ## LOW;
                  T ## HIGH ^=  Cp ## HIGH; T ## LOW ^=  Cp ## LOW;
                  T ## HIGH ^=  Dp ## HIGH; T ## LOW ^=  Dp ## LOW;
                  addX = T ## LOW; addY =  Ap ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  Ap ## HIGH;
                  switch(Rp[i]) { case 0 : XLOW = X0LOW; XHIGH = X0HIGH; break; case 1 : XLOW = X1LOW; XHIGH = X1HIGH; break; case 2 : XLOW = X2LOW; XHIGH = X2HIGH; break; case 3 : XLOW = X3LOW; XHIGH = X3HIGH; break; case 4 : XLOW = X4LOW; XHIGH = X4HIGH; break; case 5 : XLOW = X5LOW; XHIGH = X5HIGH; break; case 6 : XLOW = X6LOW; XHIGH = X6HIGH; break; case 7 : XLOW = X7LOW; XHIGH = X7HIGH; break; case 8 : XLOW = X8LOW; XHIGH = X8HIGH; break; case 9 : XLOW = X9LOW; XHIGH = X9HIGH; break; case 10 : XLOW = X10LOW; XHIGH = X10HIGH; break; case 11 : XLOW = X11LOW; XHIGH = X11HIGH; break; case 12 : XLOW = X12LOW; XHIGH = X12HIGH; break; case 13 : XLOW = X13LOW; XHIGH = X13HIGH; break; case 14 : XLOW = X14LOW; XHIGH = X14HIGH; break; case 15 : XLOW = X15LOW; XHIGH = X15HIGH; break; };
                  addX = T ## LOW; addY =  X ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  X ## HIGH;
                  //T = Ap + (Bp ^ Cp ^ Dp) + X[Rp[i]];
                  break;                                    
          }          
          Ap ## HIGH =  Ep ## HIGH; Ap ## LOW =  Ep ## LOW;
          Ep ## HIGH =  Dp ## HIGH; Ep ## LOW =  Dp ## LOW;
          Dp ## HIGH =  Cp ## HIGH; Dp ## LOW =  Cp ## LOW;
          rotMsk = mask[ (short)10]; rotH = Dp ## HIGH; rotL = Dp ## LOW; rotSh = (short) (rotMsk & ((short) (rotH >>> ((short)(16- (short)10))))); rotSl = (short) (rotMsk & ((short) (rotL >>> ((short)(16- (short)10))))); Dp ## HIGH = (short) ((rotH<<(short) (short)10) | rotSl); Dp ## LOW = (short) ((rotL<<(short) (short)10) | rotSh);
          Cp ## HIGH =  Bp ## HIGH; Cp ## LOW =  Bp ## LOW;
          Bp ## HIGH =  T ## HIGH; Bp ## LOW =  T ## LOW;
          rotMsk = mask[ sLOW]; rotH = Bp ## HIGH; rotL = Bp ## LOW; rotSh = (short) (rotMsk & ((short) (rotH >>> ((short)(16- sLOW))))); rotSl = (short) (rotMsk & ((short) (rotL >>> ((short)(16- sLOW))))); Bp ## HIGH = (short) ((rotH<<(short) sLOW) | rotSl); Bp ## LOW = (short) ((rotL<<(short) sLOW) | rotSh);
          addX = Bp ## LOW; addY =  Ap ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); Bp ## HIGH += addCarry; Bp ## LOW = addLow; Bp ## HIGH +=  Ap ## HIGH;
          






      }
      T ## HIGH =  H1 ## HIGH; T ## LOW =  H1 ## LOW;
      addX = T ## LOW; addY =  C ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  C ## HIGH;
      addX = T ## LOW; addY =  Dp ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); T ## HIGH += addCarry; T ## LOW = addLow; T ## HIGH +=  Dp ## HIGH;
      H1 ## HIGH =  H2 ## HIGH; H1 ## LOW =  H2 ## LOW;
      addX = H1 ## LOW; addY =  D ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H1 ## HIGH += addCarry; H1 ## LOW = addLow; H1 ## HIGH +=  D ## HIGH;
      addX = H1 ## LOW; addY =  Ep ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H1 ## HIGH += addCarry; H1 ## LOW = addLow; H1 ## HIGH +=  Ep ## HIGH;
      H2 ## HIGH =  H3 ## HIGH; H2 ## LOW =  H3 ## LOW;
      addX = H2 ## LOW; addY =  E ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H2 ## HIGH += addCarry; H2 ## LOW = addLow; H2 ## HIGH +=  E ## HIGH;
      addX = H2 ## LOW; addY =  Ap ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H2 ## HIGH += addCarry; H2 ## LOW = addLow; H2 ## HIGH +=  Ap ## HIGH;
      H3 ## HIGH =  H4 ## HIGH; H3 ## LOW =  H4 ## LOW;
      addX = H3 ## LOW; addY =  A ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H3 ## HIGH += addCarry; H3 ## LOW = addLow; H3 ## HIGH +=  A ## HIGH;
      addX = H3 ## LOW; addY =  Bp ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H3 ## HIGH += addCarry; H3 ## LOW = addLow; H3 ## HIGH +=  Bp ## HIGH;
      H4 ## HIGH =  H0 ## HIGH; H4 ## LOW =  H0 ## LOW;
      addX = H4 ## LOW; addY =  B ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H4 ## HIGH += addCarry; H4 ## LOW = addLow; H4 ## HIGH +=  B ## HIGH;
      addX = H4 ## LOW; addY =  Cp ## LOW; addLow = (short)(addX + addY); addCarry = (short) ((((addX & addY) | (addX & ~addY & ~addLow) | (~addX & addY & ~addLow)) >>> 15) & 1); H4 ## HIGH += addCarry; H4 ## LOW = addLow; H4 ## HIGH +=  Cp ## HIGH;
      H0 ## HIGH =  T ## HIGH; H0 ## LOW =  T ## LOW;
      






      
       target[ targetOffset++] = (byte)(H0 ## LOW);  target[ targetOffset++] = (byte)(H0 ## LOW >>> 8);  target[ targetOffset++] = (byte)(H0 ## HIGH);  target[ targetOffset++] = (byte)(H0 ## HIGH >>> 8);
       target[ targetOffset++] = (byte)(H1 ## LOW);  target[ targetOffset++] = (byte)(H1 ## LOW >>> 8);  target[ targetOffset++] = (byte)(H1 ## HIGH);  target[ targetOffset++] = (byte)(H1 ## HIGH >>> 8);
       target[ targetOffset++] = (byte)(H2 ## LOW);  target[ targetOffset++] = (byte)(H2 ## LOW >>> 8);  target[ targetOffset++] = (byte)(H2 ## HIGH);  target[ targetOffset++] = (byte)(H2 ## HIGH >>> 8);
       target[ targetOffset++] = (byte)(H3 ## LOW);  target[ targetOffset++] = (byte)(H3 ## LOW >>> 8);  target[ targetOffset++] = (byte)(H3 ## HIGH);  target[ targetOffset++] = (byte)(H3 ## HIGH >>> 8);
       target[ targetOffset++] = (byte)(H4 ## LOW);  target[ targetOffset++] = (byte)(H4 ## LOW >>> 8);  target[ targetOffset++] = (byte)(H4 ## HIGH);  target[ targetOffset++] = (byte)(H4 ## HIGH >>> 8);      
    }        
    
    // selection of message word
    private static final short[] R = {
        0,  1,  2,  3,  4,  5,  6,  7,  8, 9, 10, 11, 12, 13, 14, 15,
        7,  4, 13,  1, 10,  6, 15,  3, 12, 0,  9,  5,  2, 14, 11,  8,
        3, 10, 14,  4,  9, 15,  8,  1,  2, 7,  0,  6, 13, 11,  5, 12,
        1,  9, 11, 10,  0,  8, 12,  4, 13, 3,  7, 15, 14,  5,  6,  2,
        4,  0,  5,  9,  7, 12,  2, 10, 14, 1,  3,  8, 11,  6, 15, 13 };

    private static final short[] Rp = {
         5, 14,  7, 0, 9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
         6, 11,  3, 7, 0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
        15,  5,  1, 3, 7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
         8,  6,  4, 1, 3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
        12, 15, 10, 4, 1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11 };

    // amount for rotate left (rol)
    private static final short[] S = {
        11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
         7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
        11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
         9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 };

    private static final short[] Sp = {
         8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
         9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
         9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
         8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 };
        
    private static byte[] scratch;
    
    private static final short[] mask = {
        (short)0x0000, (short)0x0001, (short)0x0003, (short)0x0007,  
        (short)0x000F, (short)0x001F, (short)0x003F, (short)0x007F,  
        (short)0x00FF, (short)0x01FF, (short)0x03FF, (short)0x07FF,  
        (short)0x0FFF, (short)0x1FFF, (short)0x3FFF, (short)0x7FFF,  
    };          
        
    private static final byte BLOCK_SIZE = 64;
        
}

