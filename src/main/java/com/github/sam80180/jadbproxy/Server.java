package com.github.sam80180.jadbproxy;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import se.vidstige.jadb.JadbConnection;
import se.vidstige.jadb.JadbDevice;

@Slf4j
public class Server {
	public static void main(String args[]) throws Exception {
		if (args.length<1) {
			System.out.println("Serial number missing");
			System.exit(1);
		} // end if
		final String serialNumber = args[0];
		final JadbConnection jadb = new JadbConnection();
		final List<JadbDevice> devices = jadb.getDevices();
		JadbDevice device = null;
		for (JadbDevice d: devices) {
			if (!serialNumber.equals(d.getSerial())) { continue; } // end if
			device = d;
			break;
		} // end for
		if (device==null) {
			System.out.println("Device not found");
			System.exit(1);
		} // end if
		int port = 0;
		if (args.length>=2) {
			port = Integer.parseInt(args[1]);
			if (port<0 || port>65535) { port = 0; } // end if
		} // end if
		try (ServerSocket serverSocket = new ServerSocket(port)) {
	        final int serverPort = serverSocket.getLocalPort();
	        log.info("Listening on port "+serverPort);
	        while (true) {
		        Socket socket = serverSocket.accept();
		        log.info("Client connected");
		        new Session(device, socket).start();
	        } // end while
	    } catch (Exception e) {
	    	e.printStackTrace();
	    } // end try
	} // end main()
} // end class

/*
References:
https://github.com/SonicCloudOrg/sonic-android-supply/blob/master/src/adb/tcpusb.go#L106
https://github.com/tananaev/adblib/blob/master/src/main/java/com/tananaev/adblib/AdbConnection.java#L137
*/
