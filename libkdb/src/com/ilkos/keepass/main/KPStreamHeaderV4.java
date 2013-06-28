package com.ilkos.keepass.main;

import java.io.DataInput;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.ilkos.keepass.main.KPCipherFactory.CipherId;
import com.ilkos.keepass.main.KPDecompressingInputStreamFactory.CompressionAlgorithmId;
import com.ilkos.keepass.main.streams.LittleEndianDataInputStream;

public class KPStreamHeaderV4 {
	public enum Id {
		EndOfHeader(0),
		Comment(1),
		CipherID(2),
		CompressionFlags(3),
		MasterSeed(4),
		TransformSeed(5),
		TransformRounds(6),
		EncryptionIV(7),
		ProtectedStreamKey(8),
		StreamStartBytes(9),
		InnerRandomStreamID(10);

		private final int id;
	    Id(int id) { this.id = id; }
	    int getId() { return this.id; }
	}

	private CipherId cipher = null;
	private CompressionAlgorithmId compressionAlgorithm = null;
	private byte[] masterSeed = null;
	private byte[] transformSeed = null;
	private long transformRounds = -1;
	private byte[] encryptionIV = null;
	private byte[] protectedStreamKey = null;
	private byte[] streamStartBytes = null;

	public CipherId getCipher() {
		return cipher.clone();
	}

	public CompressionAlgorithmId getCompressionAlgorithm() {
		return compressionAlgorithm;
	}

	public byte[] getMasterSeed() {
		return masterSeed.clone();
	}

	public byte[] getTransformSeed() {
		return transformSeed.clone();
	}

	public long getTransformRounds() {
		return transformRounds;
	}

	public byte[] getEncryptionIV() {
		return encryptionIV.clone();
	}

	public byte[] getProtectedStreamKey() {
		return protectedStreamKey.clone();
	}

	public byte[] getStreamStartBytes() {
		return streamStartBytes.clone();
	}

	public byte[] init(InputStream is) throws IOException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		final DigestInputStream digest = new DigestInputStream(is, md);
		final LittleEndianDataInputStream led = new LittleEndianDataInputStream(digest);

		if (led.readInt() != KPInputStream.PWM_DBSIG ||
				led.readInt() != KPInputStreamV4.PWM_DBSIG_TYPE) {
			throw new IOException("Invalid signature");
		}

		final long version = led.readInt();
		// TODO check version

		while (readField(led))
			;
		
		return md.digest();
	}

	boolean readField(DataInput is) throws IOException {
		final Id headerId = Id.values()[is.readByte()];
		final int fieldSz = is.readUnsignedShort();
		
		switch (headerId) {
			case EndOfHeader:
				// consume bytes
				byte[] skip = new byte[fieldSz];
				is.readFully(skip);
				return false;
			
			case CipherID:
				if (fieldSz != 16) {
					throw new IOException("Illegal size for cipher ID");
				}
				final long msb = is.readLong();
				final long lsb = is.readLong();
				cipher = new CipherId(msb, lsb);
				break;
			
			case CompressionFlags:
				if (fieldSz != 4) {
					throw new IOException("Illegal size for compression flags");
				}
				compressionAlgorithm = new CompressionAlgorithmId(is.readInt());
				break;
			
			case MasterSeed:
				masterSeed = new byte[fieldSz];
				is.readFully(masterSeed);
				break;
			
			case TransformSeed:
				transformSeed = new byte[fieldSz];
				is.readFully(transformSeed);
				break;
				
			case TransformRounds:
				if (fieldSz != 8) {
					throw new IOException("Illegal size for transform rounds");
				}
				transformRounds = is.readLong();
				break;
				
			case EncryptionIV:
				encryptionIV = new byte[fieldSz];
				is.readFully(encryptionIV);
				break;
				
			case ProtectedStreamKey:
				protectedStreamKey = new byte[fieldSz];
				is.readFully(protectedStreamKey);
				break;
				
			case StreamStartBytes:
				streamStartBytes = new byte[fieldSz];
				is.readFully(streamStartBytes);
				break;
				
			case InnerRandomStreamID:
				if (fieldSz != 4) {
					throw new IOException("Illegal size for inner stream cipher ID");
				}
				int innerRandomStreamId = is.readInt();
				// TODO
				break;
				
			default:
				throw new IOException("Unknown header field");
		}

		return true;
	}
}