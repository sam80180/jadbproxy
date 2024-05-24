package com.github.sam80180.jadbproxy;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.concurrent.TransferQueue;
//import lombok.extern.slf4j.Slf4j;

//@Slf4j
public class PacketReader extends Thread {
	private TransferQueue<Object> C;
	private InputStream reader;
	
	public PacketReader(final InputStream reader, final TransferQueue<Object> chan) {
		this.C = chan;
		this.reader = reader;
	} // end PacketReader()
	
	@Override
	public void run() {
//log.trace("PacketReader.run(): start");
		try {
			this.drain();
		} catch (Exception e) {
			e.printStackTrace();
		} // end try
//log.trace("PacketReader.run(): end");
	} // end run()
	
	private void drain() throws Exception {
		final Method funcParseAdbMessage = Common.CLASS_ADB_MSG.getDeclaredMethod("parseAdbMessage", InputStream.class);
		funcParseAdbMessage.setAccessible(true);
		while (true) {
			final Object oMsg = funcParseAdbMessage.invoke(null, this.reader);
			this.C.add(oMsg);
		} // end while
	} // end drain()
} // end class
