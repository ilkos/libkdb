package com.ilkos.keepass.main;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPInputStream;

public class KPDecompressingInputStreamFactory {

	public static class CompressionAlgorithmId {
		private final int id;

		public CompressionAlgorithmId(int id) {
			this.id = id;
		}
		
		public boolean equals(CompressionAlgorithmId other) {
			return id == other.id;
		}
		
		public int get() {
			return id;
		}
	}
	
	private static final CompressionAlgorithmId noneId = new CompressionAlgorithmId(0);
	private static final CompressionAlgorithmId gzipId = new CompressionAlgorithmId(1);
	
	public static InputStream getDecompressedInputStream(InputStream in, CompressionAlgorithmId cid) throws IOException {
		if (cid.equals(gzipId)) {
			return new GZIPInputStream(in);
		}
		else if (cid.equals(noneId)) {
			return in;
		}
		else {
			throw new IOException("Cannot identify decompression algorithm");
		}
	}
}
