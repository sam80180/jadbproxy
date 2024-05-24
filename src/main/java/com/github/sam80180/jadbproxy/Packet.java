package com.github.sam80180.jadbproxy;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Packet {
	public static byte[] BodySkipNull(final byte[] Body) {
		final int last = Body.length-1;
		if (Body.length>=1 && Body[last]==0) {
			final byte b[] = new byte[last];
			System.arraycopy(Body, 0, b, 0, last);
			return b;
		} // end if
		return Body;
	} // end BodySkipNull()
	
	public static byte[] extractRSAPublicKeyFromPayload(final byte[] payload) throws InvalidKeyException {
		final Pattern REGEX_ADB_PUBKEY = Pattern.compile("^((?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?)\\x00?(\\s.*\\s*)?$");
		final Matcher matcher = REGEX_ADB_PUBKEY.matcher(new String(BodySkipNull(payload), StandardCharsets.UTF_8));
		if (!matcher.find()) { throw new InvalidKeyException("unrecognizable public key format"); } // end if
		return Base64.getDecoder().decode(matcher.group(1));
	} // end extractRSAPublicKeyFromPayload()
} // end class

/*
References:
https://github.com/openstf/stf/issues/1030#issuecomment-479487994
https://github.com/openstf/adbkit/blob/e1cb244e71ef8b21694cdd16ab9784454d9c2100/src/adb/auth.coffee#L25
*/
