package com.github.sam80180.jadbproxy;

import com.tananaev.adblib.AdbProtocol;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Common {
	public static Class<?> CLASS_ADB_MSG;
	
	static {
		try {
			CLASS_ADB_MSG = Class.forName("com.tananaev.adblib.AdbProtocol$AdbMessage");
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} // end try
	} // end static
	
	public static int swapUint32(final int n) { // https://stackoverflow.com/a/29792973/12857692
		return Integer.reverseBytes(n);
	} // end swapUint32()
	
	public static String base64encode(final byte[] s) {
		return Base64.getEncoder().encodeToString(s);
	} // end base64encode()
	
	public static byte[] adbStr2bytes(final String s) {
		return String.format("%04x%s", s.length(), s).getBytes(StandardCharsets.UTF_8);
	} // end adbStr2bytes()
	
	public static String cmd2txt(final int c) throws Exception {
		final Field[] declaredFields = AdbProtocol.class.getDeclaredFields();
		for (Field field : declaredFields) {
			final int modifiers = field.getModifiers();
			final String fieldName = field.getName();
		    if (!Modifier.isStatic(modifiers) || !Modifier.isFinal(modifiers) || !fieldName.startsWith("CMD_")) { continue; } // end if
		    field.setAccessible(true);
		    final int val = field.getInt(null);
		    if (val==c) { return fieldName; } // end if
		} // end for
		return null;
	} // end cmd2txt()
} // end class
