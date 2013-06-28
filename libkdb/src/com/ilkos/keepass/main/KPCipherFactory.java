package com.ilkos.keepass.main;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KPCipherFactory {
	
	public static class CipherId {
		final long msb;
		final long lsb;
		CipherId(long msb, long lsb) {
			this.msb = msb;
			this.lsb = lsb;
		}

		public boolean equals(CipherId other) {
			return this.msb == other.msb &&
					this.lsb == other.lsb;
		}
		
		public CipherId clone() {
			return new CipherId(msb, lsb);
		}
	}

	private static final CipherId aesId = new CipherId(0x504371bfe6f2c131L, 0xff5afc6a210558beL);

	public static Cipher getFromCipherId(CipherId id, int mode, byte[] key, byte[] iv)
					throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		if (id.equals(aesId)) {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
			return cipher;
		}
		else {
			throw new NoSuchAlgorithmException("Algorithm not recognised");
		}
	}
}
