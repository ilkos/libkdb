package com.ilkos.keepass.main.streams;

import java.io.DataInput;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HashedBlockInputStream extends InputStream {
	private final DataInput in;
	
	private byte[] buffer = null;
	private int bufferIdx = -1;
	private int currentBlock = 0;

	public HashedBlockInputStream(DataInput in) {
		this.in = in;
	}

	@Override
	public int read() throws IOException {
		if (buffer == null || bufferIdx >= buffer.length) {
			if (!readBlock()) {
				return -1;
			}
		}

		return buffer[bufferIdx++] & 0xff;
	}

	@Override
	public long skip(long n) throws IOException {
		return 0;
	}

	private boolean readBlock() throws IOException {
		int blockNumber = in.readInt();
		if (blockNumber != currentBlock) {
			throw new IOException("Blocks do not match " + blockNumber + " " + currentBlock);
		}
		++currentBlock;
		
		byte[] storedHash = new byte[32];
		in.readFully(storedHash);
		
		int bufferSize = in.readInt();
		if (bufferSize < 0) {
			throw new IOException("Invalid buffer size " + bufferSize);
		}
		else if (bufferSize == 0) {
			for (int i = 0; i < storedHash.length; ++i) {
				if (storedHash[i] != 0) {
					throw new IOException("Hash does not match EOF");
				}
			}
			
			return false;
		}
		
		buffer = new byte[bufferSize];
		bufferIdx = 0;
		in.readFully(buffer);
		
		try {
			if (!Arrays.equals(storedHash, MessageDigest.getInstance("SHA-256").digest(buffer))) {
				throw new IOException("Hashes do not match");
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new IOException("Cannot instantiate hash");
		}

		return true;
	}
}
