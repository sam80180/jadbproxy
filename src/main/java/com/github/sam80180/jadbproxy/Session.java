package com.github.sam80180.jadbproxy;

import com.tananaev.adblib.AdbProtocol;
import io.github.muntashirakon.adb.AndroidPubkey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.TransferQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.MapConfiguration;
import se.vidstige.jadb.JadbDevice;

@Slf4j
public class Session extends Thread {
	public static final int A_VERSION = 0x01000001;
	public static final int MAX_PAYLOAD_V1 = 4*1024;
	private static AtomicLong LOCAL_ID_GENERATOR = new AtomicLong(0);
	private static final int TOKEN_LENGTH = 20;
	JadbDevice device;
	private Configuration devProps;
	private Socket socket;
	private OutputStream clientOutput;
	private InputStream clientInput;
	private int version = 1;
	int maxPayload = 4096;
	private byte token[];
	private byte signature[];
	private Map<Integer, TransportService> services = new ConcurrentHashMap<>();
	private boolean authorized = false;
	private RSAPublicKey auth_key;
	
	public Session(final JadbDevice d, final Socket s) throws Exception {
		this.device = d;
		this.devProps = new MapConfiguration(new HashMap<String, String>());
		this.refreshPropertyCache();
		this.socket = s;
		this.socket.setTcpNoDelay(true); // https://github.com/tananaev/adblib/blob/master/src/main/java/com/tananaev/adblib/AdbConnection.java#L118C16-L118C36
		this.token = new byte[TOKEN_LENGTH];
		new Random().nextBytes(this.token);
		log.info("Session token= {}", Common.base64encode(this.token));
	} // end JadbProxy()
	
	public void writePacket(final byte packet[]) throws IOException {
		this.clientOutput.write(packet);
		this.clientOutput.flush();
	} // end writePacket()
	
	@Override
	public void run() {
		try {
			this.clientInput = this.socket.getInputStream();
			this.clientOutput = this.socket.getOutputStream();
			final TransferQueue<Object> C = new LinkedTransferQueue<>();
			new PacketReader(this.clientInput, C).start();
			while (true) {
				final Object oMsg = C.take();
				final Field fAdbCmd = Common.CLASS_ADB_MSG.getDeclaredField("command");
				fAdbCmd.setAccessible(true);
				final int adbCmd = fAdbCmd.getInt(oMsg);
				log.debug("Session.run(): command= {}", Common.cmd2txt(adbCmd));
				switch (adbCmd) {
    				case AdbProtocol.CMD_CNXN:
                    	this.onConnection(oMsg);
                    	break;
                    case AdbProtocol.CMD_AUTH:
                    	this.onAuth(oMsg);
                    	break;
                    case AdbProtocol.CMD_OPEN:
                    	this.onOpen(oMsg);
                    	break;
                    case AdbProtocol.CMD_OKAY:
                    case AdbProtocol.CMD_WRTE:
                    	this.forwardServicePacket(oMsg);
                    	break;
                	case AdbProtocol.CMD_CLSE:
                		this.forwardServicePacket(oMsg);
                		final Field fArg1 = Common.CLASS_ADB_MSG.getDeclaredField("arg1");
                    	fArg1.setAccessible(true);
                    	this.services.remove(fArg1.getInt(oMsg));
                    	break;
                    default:
                    	log.warn("Unknown command: {}", adbCmd);
                    	return;
				} // end switch
			} // end while
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				this.socket.close();
				log.info("Session closed (token= {})", Common.base64encode(this.token));
			} catch (Exception e) {
				e.printStackTrace();
			} // end try
		} // end try
	} // end run()
	
	private void onConnection(final Object oMsg) throws Exception  {
		this.send_connect(); // workaround to this problem (https://github.com/openstf/stf/issues/973)
		final boolean auth_required = this.devProps.getBoolean("ro.adb.secure", false);
		if (!auth_required) { // https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/adb.cpp#397
			log.info("Authentication not required");
			this.authVerified(); // 直接假裝成功
			return;
		} // end if
		final Field fArg0 = Common.CLASS_ADB_MSG.getDeclaredField("arg0");
    	fArg0.setAccessible(true);
    	final Field fArg1 = Common.CLASS_ADB_MSG.getDeclaredField("arg1");
    	fArg1.setAccessible(true);
		this.version = fArg0.getInt(oMsg);
    	this.maxPayload = fArg1.getInt(oMsg);
    	if (this.maxPayload>0xFFFF) { this.maxPayload = 0xFFFF; } // end if
    	log.debug("version= {}, maxPayload= {}", this.version, this.maxPayload);
		this.send_auth_request();
	} // end onConnection()
	
	private void send_auth_request() throws IOException {
		final byte packet[] = AdbProtocol.generateAuth(AdbProtocol.AUTH_TYPE_TOKEN, this.token);
		this.writePacket(packet);
	} // end send_auth_request()
	
	private void onAuth(final Object oMsg) throws Exception {
		final Field fArg0 = Common.CLASS_ADB_MSG.getDeclaredField("arg0");
    	fArg0.setAccessible(true);
    	final int auth_type = fArg0.getInt(oMsg);
    	switch (auth_type) {
    		case AdbProtocol.AUTH_TYPE_SIGNATURE:
    			final Field fPayloadSig = Common.CLASS_ADB_MSG.getDeclaredField("payload");
    			fPayloadSig.setAccessible(true);
    			this.signature = (byte[])fPayloadSig.get(oMsg);
    			log.debug("Received signature= {}", Common.base64encode(this.signature));
    			this.send_auth_request();
    			break;
    		case AdbProtocol.AUTH_TYPE_RSA_PUBLIC:
    			if (this.signature==null || this.signature.length<=0) {
    				throw new IllegalStateException("public key sent before signature");
    			} // end if
    			final Field fPayloadAuthRsa = Common.CLASS_ADB_MSG.getDeclaredField("payload");
    			fPayloadAuthRsa.setAccessible(true);
    			final byte[] rawPubKey = (byte[])fPayloadAuthRsa.get(oMsg);
    			if (rawPubKey==null || rawPubKey.length<2) {
    				throw new IllegalStateException("empty RSA public key");
    			} // end if
    			log.debug("Received RSA public key= {}", new String(rawPubKey, StandardCharsets.UTF_8));
    			this.adbd_auth_confirm_key(rawPubKey);
    			if (AndroidPubkey.validate(this.auth_key, this.token, this.signature)) {
    				log.info("Signature verified");
    				this.send_connect();
        			this.authVerified();
    			} else {
    				throw new SocketException("signature mismatch");
    			} // end if
				break;
    		default:
    			throw new IllegalArgumentException("unknown authentication method "+auth_type);
    	} // end switch
	} // end onAuth()
	
	private void adbd_auth_confirm_key(final byte rawPubKey[]) throws Exception {
		final byte b[] = Packet.extractRSAPublicKeyFromPayload(rawPubKey);
		this.auth_key = AndroidPubkey.decode(b);
	} // end adbd_auth_confirm_key()
	
	private void send_connect() throws IOException {
		final List<String> deviceProperties = new ArrayList<String>();
		final String pickProps[] = new String[] {"ro.product.name", "ro.product.model", "ro.product.device"};
		for (String prop: pickProps) {
			final String propVal = this.devProps.getString(prop, "");
			deviceProperties.add(prop+"="+propVal);
		} // end for
		deviceProperties.add("features=shell_v2,cmd");
		final String connection_str = "device::"+String.join(";", deviceProperties);
		final int lenConnStr = connection_str.length();
		if (lenConnStr>MAX_PAYLOAD_V1) {
			throw new SocketException(String.format("connection banner is too long (length = %d)", lenConnStr));
		} // end if
		final byte outputPayload[] = connection_str.getBytes();
		final byte packet[] = AdbProtocol.generateMessage(AdbProtocol.CMD_CNXN, A_VERSION, this.maxPayload, outputPayload);
		this.writePacket(packet);
	} // end send_connect()
	
	private void authVerified() throws Exception {
		this.authorized = true;
	} // end authVerified()
	
	private void onOpen(final Object pkt) throws Exception {
		if (!this.authorized) { throw new SecurityException("unauthorized"); } // end if
		final Field fPayload = Common.CLASS_ADB_MSG.getDeclaredField("payload");
		fPayload.setAccessible(true);
		final byte body[] = (byte[])fPayload.get(pkt);
		if (body==null || body.length<2) {
			throw new IllegalArgumentException("empty service name");
		} // end if
		final String serviceName = new String(Packet.BodySkipNull(body), StandardCharsets.UTF_8);
		final Field fArg0 = Common.CLASS_ADB_MSG.getDeclaredField("arg0");
    	fArg0.setAccessible(true);
    	final int remoteId = fArg0.getInt(pkt);
    	final int localId = (int)LOCAL_ID_GENERATOR.incrementAndGet();
    	log.debug("Calling #{}, remoteId: {}, localId: {}", serviceName, remoteId, localId);
    	final TransportService svc = new TransportService(localId, remoteId, this);
    	this.services.put(localId, svc);
    	svc.handle(pkt);
	} // end onOpen()
	
	private void forwardServicePacket(final Object pkt) throws Exception {
		if (!this.authorized) { throw new SecurityException("unauthorized"); } // end if
		final Field fArg1 = Common.CLASS_ADB_MSG.getDeclaredField("arg1");
    	fArg1.setAccessible(true);
    	final int localId = fArg1.getInt(pkt);
    	final TransportService service = this.services.get(localId);
    	if (service==null) {
    		log.warn("Received packet of already closed service: localId= {}", localId);
    		return;
    	} // end if
    	service.handle(pkt);
	} // end forwardServicePacket()
	
	private void refreshPropertyCache() {
		try {
			final BufferedReader cmdstdout = new BufferedReader(new InputStreamReader(this.device.execute("getprop")));
			final String escapedLeftBracket = Pattern.quote("[");
			final String escapedRightBracket = Pattern.quote("]");
			final Pattern patternGetprop = Pattern.compile(escapedLeftBracket+"(.+)"+escapedRightBracket+": "+escapedLeftBracket+"(.*)"+escapedRightBracket, Pattern.CASE_INSENSITIVE);
			String lineProp = null;
			final Map<String, String> newProps = new HashMap<>();
			while ((lineProp=cmdstdout.readLine())!=null) {
				final Matcher match = patternGetprop.matcher(lineProp);
				if (!match.find()) { continue; } // end if
				newProps.put(match.group(1), match.group(2));
			} // end while
			cmdstdout.close();
			this.devProps = new MapConfiguration(newProps);
		} catch (Exception e) {
			e.printStackTrace();
		} // end try
	} // end refreshPropertyCache()
} // end class

/*
References:
https://github.com/openstf/adbkit/blob/e1cb244e71ef8b21694cdd16ab9784454d9c2100/src/adb/tcpusb/socket.coffee
https://github.com/SonicCloudOrg/sonic-android-supply/blob/master/src/adb/tcpusb.go
https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/daemon/auth.cpp
*/
