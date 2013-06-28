package com.ilkos.keepass.main;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

public class KPKeyTransformation {

	static byte[] apply(byte[] key, byte[] seed, long rounds)
			throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException {
		Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
		aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(seed, "AES"));
		
		byte[] transformed = new byte[key.length];
		for (long i = 0; i < rounds; ++i) {
			try {
				aes.update(key, 0, key.length, transformed);
			} catch (ShortBufferException e) {
				e.printStackTrace();
			}
			System.arraycopy(transformed, 0, key, 0, key.length);
		}
		
		return MessageDigest.getInstance("SHA-256").digest(key);
	}
}
