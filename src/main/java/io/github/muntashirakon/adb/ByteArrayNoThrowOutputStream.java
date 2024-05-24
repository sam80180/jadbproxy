// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0
package io.github.muntashirakon.adb;

import java.io.ByteArrayOutputStream;

class ByteArrayNoThrowOutputStream extends ByteArrayOutputStream {
    public ByteArrayNoThrowOutputStream() {
        super();
    } // end ByteArrayNoThrowOutputStream()

    public ByteArrayNoThrowOutputStream(final int size) {
        super(size);
    } // end ByteArrayNoThrowOutputStream()

    @Override
    public void write(final byte[] b) {
        this.write(b, 0, b.length);
    } // end write()

    @Override
    public void close() {} // end close()
} // end class

/*
References:
https://github.com/MuntashirAkon/libadb-android/blob/master/libadb/src/main/java/io/github/muntashirakon/adb/ByteArrayNoThrowOutputStream.java
*/
