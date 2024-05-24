// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0
package io.github.muntashirakon.adb;

import java.io.UnsupportedEncodingException;
import java.nio.charset.IllegalCharsetNameException;

final class StringCompat {
    public static byte[] getBytes(String text, String charsetName) {
    	try {
            return text.getBytes(charsetName);
        } catch (UnsupportedEncodingException e) {
            throw (IllegalCharsetNameException) new IllegalCharsetNameException("Illegal charset "+charsetName).initCause(e);
        } // end try
    } // end getBytes()
} // end class

/*
References:
https://github.com/MuntashirAkon/libadb-android/blob/master/libadb/src/main/java/io/github/muntashirakon/adb/StringCompat.java
*/
