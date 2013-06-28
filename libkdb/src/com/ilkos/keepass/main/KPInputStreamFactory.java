package com.ilkos.keepass.main;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;

import com.ilkos.keepass.main.exceptions.InvalidPasswordException;
import com.ilkos.keepass.main.streams.HashedBlockInputStream;
import com.ilkos.keepass.main.streams.LittleEndianDataInputStream;

public class KPInputStreamFactory {

	public static KPInputStream getInputStream(InputStream istream, String password, File keyfile)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidPasswordException, InvalidAlgorithmParameterException {
		if (!istream.markSupported()) {
			throw new IOException("Stream does not support mark");
		}
		istream.mark(8);

		final LittleEndianDataInputStream is = new LittleEndianDataInputStream(istream);
		if (is.readInt() != KPInputStream.PWM_DBSIG) {
			throw new IOException("Input stream not a KeePass file");
		}		
		final int typeFlag = is.readInt();

		istream.reset();
		if (typeFlag == KPInputStreamV4.PWM_DBSIG_TYPE) {
			return getInputStreamV4(istream, password, keyfile);
		}

		throw new IOException("Type not recognised");
	}

	private static KPInputStreamV4 getInputStreamV4(InputStream in, String password, File keyfile)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidPasswordException, InvalidAlgorithmParameterException {
		final KPStreamHeaderV4 header = new KPStreamHeaderV4();
		final byte[] headerHash = header.init(in);
		
		final byte[] pwHash = hashPassword(password);
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		final byte[] masterKey = md.digest(pwHash);
		
		md.reset();
		md.update(header.getMasterSeed());
		md.update(KPKeyTransformation.apply(masterKey,
				header.getTransformSeed(), 
				header.getTransformRounds()));

		InputStream decrypted = new CipherInputStream(in, 
				KPCipherFactory.getFromCipherId(header.getCipher(),
						Cipher.DECRYPT_MODE,
						md.digest(),
						header.getEncryptionIV()));
		
		byte[] dStartBytes = new byte[32];
		if (decrypted.read(dStartBytes, 0, 32) != 32) {
			throw new IOException("Invalid size read");
		}

		if (!Arrays.equals(dStartBytes, header.getStreamStartBytes())) {
			throw new InvalidPasswordException();
		}

		HashedBlockInputStream hashedInput = new HashedBlockInputStream(new LittleEndianDataInputStream(decrypted));
		return new KPInputStreamV4(header,
				KPDecompressingInputStreamFactory.getDecompressedInputStream(
						hashedInput,
						header.getCompressionAlgorithm()),
					md.digest());
	}

	static byte[] hashPassword(String password)
			throws IOException, NoSuchAlgorithmException {
		if (password == null || password.isEmpty()) {
			throw new IllegalArgumentException();
		}
		byte[] raw = password.getBytes("UTF-8");
		return MessageDigest.getInstance("SHA-256").digest(raw);
	}
}
