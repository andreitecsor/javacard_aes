/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */

package hw.ism.javacard.aes;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.annotations.*;
import javacardx.crypto.Cipher;

import static hw.ism.javacard.aes.ProjectAesAppletStrings.*;

/**
 * Applet class
 * 
 * @author andreitecsor
 */
@StringPool(value = { @StringDef(name = "Package", value = "hw.ism.javacard.aes"),
		@StringDef(name = "AppletName", value = "ProjectAesApplet") },
		// Insert your strings here
		name = "ProjectAesAppletStrings")
public class ProjectAesApplet extends Applet {
	final static byte AES_CLA_APPLET = (byte) 0x80;

	final static byte CHECK_PIN_MODE = (byte) 0x01;
	final static byte ENCRYPT_MODE = (byte) 0x02;
	final static byte DECRYPT_MODE = (byte) 0x03;

	final static byte MAX_PIN_SIZE = (byte) 0x08;
	final static byte PIN_TRY_LIMIT = (byte) 0x05;

	final static short SW_PIN_VERIFICATION_FAILED = 0x6300;
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	AESKey aesKey;
	Cipher aesCipher;
	OwnerPIN pin;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ProjectAesApplet(bArray, bOffset);
	}

	protected ProjectAesApplet(byte[] bArray, short bOffset) {
		bOffset -= 1;
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		byte pinLength = bArray[bOffset++];
		pin.update(bArray, bOffset, pinLength);

		bOffset += pinLength;

		aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, true);
		aesKey.setKey(bArray, ++bOffset);

		aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		register();
	}

	@Override
	public void process(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		if (selectingApplet()) {
			return;
		}
		if (buffer[ISO7816.OFFSET_CLA] != AES_CLA_APPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		switch (buffer[ISO7816.OFFSET_INS]) {
		case CHECK_PIN_MODE: {
			checkPIN(apdu);
			return;
		}
		case ENCRYPT_MODE: {
			encryptAES(apdu);
			return;
		}
		case DECRYPT_MODE: {
			decryptAES(apdu);
			return;
		}
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	@Override
	public boolean select() {
		if (pin.getTriesRemaining() == 0) {
			return false;
		}
		return true;
	}

	@Override
	public void deselect() {
		pin.reset();
	}

	private void checkPIN(APDU apdu) {
		byte[] pinBuff = apdu.getBuffer();
		byte length = (byte) (apdu.setIncomingAndReceive());
		if (pin.check(pinBuff, ISO7816.OFFSET_CDATA, length) == false) {
			ISOException.throwIt(SW_PIN_VERIFICATION_FAILED);
		}
	}

	private void encryptAES(APDU apdu) {
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		byte[] inBuff = apdu.getBuffer();
		short inLength = apdu.setIncomingAndReceive();
		byte[] outBuff = new byte[64];
		aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
		aesCipher.update(inBuff, ISO7816.OFFSET_CDATA, (short) (inLength * 2), outBuff, (short) 0);
		Util.arrayCopy(outBuff, (short) 0, inBuff, ISO7816.OFFSET_CDATA, (short) 64);
		aesCipher.doFinal(inBuff, ISO7816.OFFSET_CDATA, inLength, outBuff, (short) 0);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 32);
	}

	private void decryptAES(APDU apdu) {
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		byte[] inBuff = apdu.getBuffer();
		short inLength = apdu.setIncomingAndReceive();
		byte[] outBuff = new byte[64];
		aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
		aesCipher.doFinal(inBuff, ISO7816.OFFSET_CDATA, inLength, outBuff, (short) 0);
		Util.arrayCopy(outBuff, (short) 0, inBuff, ISO7816.OFFSET_CDATA, (short) 32);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 16);
	}

}
