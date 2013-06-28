package com.ilkos.keepass.test;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import org.junit.Test;

import com.ilkos.keepass.main.KPInputStream;
import com.ilkos.keepass.main.KPInputStreamFactory;
import com.ilkos.keepass.main.exceptions.InvalidPasswordException;

public class DatabaseIO4Test {

	@Test
	public void testLoad() throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidPasswordException, InvalidAlgorithmParameterException {
		InputStream is = new BufferedInputStream(new FileInputStream("src/com/ilkos/keepass/test/test.kdbx"));
		KPInputStream dbio = KPInputStreamFactory.getInputStream(is, "test", null);
		
		System.out.print(convertStreamToString(dbio));
	}
	
	public static String convertStreamToString(java.io.InputStream is) {
	    java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
	    return s.hasNext() ? s.next() : "";
	}
}
