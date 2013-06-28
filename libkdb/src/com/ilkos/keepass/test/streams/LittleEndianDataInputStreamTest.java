package com.ilkos.keepass.test.streams;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.junit.Test;

import com.ilkos.keepass.main.streams.LittleEndianDataInputStream;

public class LittleEndianDataInputStreamTest {

	@Test
	public void testReadInt() throws IOException {
		byte[] w = new byte[] {(byte)0x03,
				(byte)0xd9,
				(byte)0xa2,
				(byte)0x9a,
				(byte)0x67,
				(byte)0xfb,
				(byte)0x4b,
				(byte)0xb5};
		ByteArrayInputStream testInput = new ByteArrayInputStream(w);
		final LittleEndianDataInputStream s = new LittleEndianDataInputStream(testInput);
		assertEquals(s.readInt(), 0x9aa2d903);
		assertEquals(s.readInt(), 0xb54bfb67);
	}

}
