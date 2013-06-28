package com.ilkos.keepass.main;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;


public class KPInputStreamV4 extends KPInputStream {
	public static final int PWM_DBSIG_TYPE = 0xB54BFB67;
	private final KPStreamHeaderV4 header;
	private final InputStream in;
	private final byte[] key;

	public KPInputStreamV4(KPStreamHeaderV4 header, InputStream in, byte[] key)
			throws IOException, NoSuchAlgorithmException {
		this.header = header;
		this.key = key;
		this.in = in;
	}

	public KPStreamHeaderV4 getHeader() {
		return header;
	}

	@Override
	public int read() throws IOException {
		return in.read();
	}
}
