package com.ilkos.keepass.main.streams;

import java.io.DataInput;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class LittleEndianDataInputStream extends FilterInputStream implements DataInput {
	final byte[] tmp = new byte[8];

	public LittleEndianDataInputStream(InputStream in) {
		super(in);
	}

	@Override
	public boolean readBoolean() throws IOException {
		return readByte() != 0;
	}

	@Override
	public byte readByte() throws IOException {
		int r = in.read();
		if (r == -1) {
			throw new IOException("EOF");
		}
		return (byte) (r & 0xff);
	}

	@Override
	public char readChar() throws IOException {
		byte b = readByte();
		byte a = readByte();
		return (char) ((a << 8) | (b & 0xff));
	}

	@Override
	public double readDouble() throws IOException {
		return Double.longBitsToDouble(readLong());
	}

	@Override
	public float readFloat() throws IOException {
		return Float.intBitsToFloat(readInt());
	}

	@Override
	public void readFully(byte[] b) throws IOException {
		if (b == null) {
			throw new NullPointerException();
		}

		for (int i = 0; i < b.length; ++i) {
			b[i] = readByte();
		}
	}

	@Override
	public void readFully(byte[] b, int off, int len) throws IOException {
		if (b == null) {
			throw new NullPointerException();
		}
		
		if (off < 0 || len < 0 || off + len > b.length) {
			throw new IndexOutOfBoundsException();
		}
		
		for (int i = 0; i < len; ++i) {
			b[off + i] = readByte();
		}
	}

	@Override
	public int readInt() throws IOException {
		readFully(tmp, 0, 4);
		return (((tmp[3] & 0xff) << 24) | ((tmp[2] & 0xff) << 16) |
				((tmp[1] & 0xff) << 8) | (tmp[0] & 0xff));
	}

	@Override
	public String readLine() throws IOException {
		throw new IOException("Not implemented");
	}

	@Override
	public long readLong() throws IOException {
		 readFully(tmp, 0, 8);
		 return (((long)(tmp[7] & 0xff) << 56) |
				  ((long)(tmp[6] & 0xff) << 48) |
				  ((long)(tmp[5] & 0xff) << 40) |
				  ((long)(tmp[4] & 0xff) << 32) |
				  ((long)(tmp[3] & 0xff) << 24) |
				  ((long)(tmp[2] & 0xff) << 16) |
				  ((long)(tmp[1] & 0xff) <<  8) |
				  ((long)(tmp[0] & 0xff)));
	}

	@Override
	public short readShort() throws IOException {
		byte b = readByte();
		byte a = readByte();
		return (short) ((a << 8) | (b & 0xff));
	}

	@Override
	public String readUTF() throws IOException {
		throw new IOException("Not implemented");
	}

	@Override
	public int readUnsignedByte() throws IOException {
		int r = in.read();
		if (r == -1) {
			throw new EOFException();
		}
		
		return r;
	}

	@Override
	public int readUnsignedShort() throws IOException {
		byte b = readByte();
		byte a = readByte();
		return (((a & 0xff) << 8) | (b & 0xff));
	}

	@Override
	public int skipBytes(int n) throws IOException {
		return (int) in.skip(n);
	}

}
