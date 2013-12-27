package com.yubico.ykneo.curves;

/* Copyright (c) 2013 Yubico AB 
 * All rights reserved.
 */

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.Signature;

public class YkneoCurves extends Applet {
	public static final short _0 = 0;
	
	public static final byte GENERATE = 1;
	public static final byte SIGN = 2;

	private KeyPair brainpoolp256r1;
	private KeyPair secp256r1;
	private KeyPair brainpoolp320r1;
	private KeyPair brainpoolp256t1;
	private KeyPair secp256k1;
	private KeyPair gost2001;
	
	private Signature signature;

	public YkneoCurves() {
		brainpoolp256r1 = BrainpoolP256r1.newKeyPair();
		secp256r1 = SecP256r1.newKeyPair();
		brainpoolp320r1 = BrainpoolP320r1.newKeyPair();
		brainpoolp256t1 = BrainpoolP256t1.newKeyPair();
		secp256k1 = SecP256k1.newKeyPair();
		gost2001 = Gost2001.newKeyPair();
		
		signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new YkneoCurves().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) throws ISOException {
		if(selectingApplet()) {
			return;
		}

		short sendlen = 0;
		short recvlen = apdu.setIncomingAndReceive();
		byte[] buf = apdu.getBuffer();
		byte ins = buf[ISO7816.OFFSET_INS];
		
		KeyPair pair = null;
		byte operation = 0;
		if((ins & 0x0f) == 0x01) {
			operation = GENERATE;
		} else if((ins & 0x0f) == 0x02) {
			operation = SIGN;
		}
		

		switch(ins) {
		case 0x01:
		case 0x02:
			pair = brainpoolp256r1;
			break;
		case 0x11:
		case 0x12:
			pair = secp256r1;
			break;
		case 0x21:
		case 0x22:
			pair = brainpoolp320r1;
			break;
		case 0x31:
		case 0x32:
			pair = brainpoolp256t1;
			break;
		case 0x41:
		case 0x42:
			pair = secp256k1;
			break;
		case 0x51:
		case 0x52:
			pair = gost2001;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		if(operation == GENERATE) {
			pair.genKeyPair();
			ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
			sendlen = pubKey.getW(buf, _0);
		} else if(operation == SIGN) {
			signature.init(pair.getPrivate(), Signature.MODE_SIGN);
			sendlen = signature.sign(buf, ISO7816.OFFSET_CDATA, recvlen, buf, _0);
		}
		if(sendlen > 0) {
			apdu.setOutgoingAndSend(_0, sendlen);
		}
	}
}
