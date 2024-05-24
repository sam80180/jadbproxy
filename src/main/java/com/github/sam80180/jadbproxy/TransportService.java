package com.github.sam80180.jadbproxy;

import com.tananaev.adblib.AdbProtocol;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;

@Slf4j
public class TransportService {
	private int remoteId;
	private int localId;
	private Session session;
	private ADBConn transport;
	
	public TransportService(final int localId, final int remoteId, Session sess) {
		this.localId = localId;
		this.remoteId = remoteId;
		this.session = sess;
	} // end TransportService()
	
	public void handle(final Object pkt) throws Exception {
		final Field fAdbCmd = Common.CLASS_ADB_MSG.getDeclaredField("command");
		fAdbCmd.setAccessible(true);
		final int adbCmd = fAdbCmd.getInt(pkt);
//log.debug("TransportService.handle(): command= {}", Common.cmd2txt(adbCmd));
		switch (adbCmd) {
			case AdbProtocol.CMD_OPEN:
				this.handleOpenPacket(pkt);
				break;
			case AdbProtocol.CMD_OKAY:
				
				break;
			case AdbProtocol.CMD_WRTE:
				this.handleWritePacket(pkt);
				break;
			case AdbProtocol.CMD_CLSE:
				this.handleClosePacket(pkt);
				break;
		} // end switch
	} // end handle()
	
	private void handleOpenPacket(final Object pkt) throws Exception {
//log.trace("TransportService.handleOpenPacket(): start");
		this.writePacket(AdbProtocol.CMD_OKAY, null);
		final Field fPayload = Common.CLASS_ADB_MSG.getDeclaredField("payload");
		fPayload.setAccessible(true);
		final String serviceName = new String(Packet.BodySkipNull((byte[])fPayload.get(pkt)), StandardCharsets.UTF_8);
		if (serviceName.startsWith("reverse:")) {
			log.warn("The 'reverse' service is not supported.");
			this.writeError("reverse service not supported");
			this.end();
			return;
		} // end if
		this.transport = new ADBConn(this.session.device);
		this.transport.OpenTransport();
		this.transport.Encode(serviceName.getBytes(StandardCharsets.UTF_8));
		this.transport.CheckOKAY();
		final TransportService that = this;
		new Thread() {
			@Override
			public void run() {
//log.trace("TransportService.handleOpenPacket.Thread.run(): start");
				final byte[] buf = new byte[that.session.maxPayload];
				do {
					try {
						final int n = that.transport.Read(buf);
//log.debug("read device input, length= {}", n);
						if (n>0) {
							byte[] data = buf;
							if (n<that.session.maxPayload) {
								data = new byte[n];
								System.arraycopy(buf, 0, data, 0, n);
							} // end if
//log.debug("from device=[{}], localId= {}, remotdId= {}", new String(data, StandardCharsets.UTF_8), that.localId, that.remoteId);
							that.writePacket(AdbProtocol.CMD_WRTE, data);
						} else if (n<0) { // EOS
							that.end();
							break;
						} // end if
					} catch (Exception e) {
						e.printStackTrace();
						try {
							that.end();
						} catch (Exception e1) {
							e1.printStackTrace();
						} // end try
						break;
					} // end try
				} while (true);
//log.trace("TransportService.handleOpenPacket.Thread.run(): end");
			} // end run()
		}.start();
//log.trace("TransportService.handleOpenPacket(): end");
	} // end handleOpenPacket()
	
	private void handleWritePacket(final Object pkt) throws Exception {
		this.writePacket(AdbProtocol.CMD_OKAY, null);
		final Field fPayload = Common.CLASS_ADB_MSG.getDeclaredField("payload");
		fPayload.setAccessible(true);
		this.transport.Write((byte[])fPayload.get(pkt));
	} // end handleWritePacket()
	
	private void handleClosePacket(final Object pkt) throws Exception {
		this.end();
	} // end handleClosePacket()
	
	private void writeError(final String message) throws Exception {
		final byte[] b0 = "FAIL".getBytes(StandardCharsets.UTF_8);
		final byte[] b1 = Common.adbStr2bytes(message);
		this.writePacket(AdbProtocol.CMD_WRTE, ArrayUtils.addAll(b0, b1));
	} // end writeError()
	
	private void writePacket(final int oper, final byte[] data) throws Exception {
		final byte packet[] = AdbProtocol.generateMessage(oper, this.localId, this.remoteId, data);
		this.session.writePacket(packet);
	} // end writePacket()
	
	private void end() throws Exception {
		if (this.transport!=null) { this.transport.close(); } // end if
		this.writePacket(AdbProtocol.CMD_CLSE, null);
	} // end end()
} // end class
