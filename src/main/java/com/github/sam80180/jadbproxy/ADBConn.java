package com.github.sam80180.jadbproxy;

import java.io.DataInputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import se.vidstige.jadb.JadbDevice;

public class ADBConn  {
	private JadbDevice device;
	private Object transport;
	
	public ADBConn(final JadbDevice jadb) {
		this.device = jadb;
	} // end ADBConn()
	
	public void OpenTransport() throws Exception {
		final Method funcGetTransport = JadbDevice.class.getDeclaredMethod("getTransport");
		funcGetTransport.setAccessible(true);
		this.transport = funcGetTransport.invoke(this.device);
	} // end OpenTransport()
	
	public void close() throws Exception {
		final Method funcClose = this.transport.getClass().getDeclaredMethod("close");
		funcClose.setAccessible(true);
		funcClose.invoke(this.transport);
	} // end close()
	
	public void CheckOKAY() throws Exception {
		final Method funcVerifyResponse = this.transport.getClass().getDeclaredMethod("verifyResponse");
		funcVerifyResponse.setAccessible(true);
		funcVerifyResponse.invoke(this.transport);
	} // end CheckOKAY()
	
	public void Encode(final byte[] v) throws Exception {
		this.EncodeString(new String(v, StandardCharsets.UTF_8));
	} // end Encode()
	
	public void EncodeString(final String s) throws Exception {
		this.Write(Common.adbStr2bytes(s));
	} // end EncodeString()
	
	public void Write(final byte[] b) throws Exception {
		final Field fieldOutputStream = this.transport.getClass().getDeclaredField("outputStream");
		fieldOutputStream.setAccessible(true);
		final OutputStream outputStream = (OutputStream)fieldOutputStream.get(this.transport);
		outputStream.write(b);
		outputStream.flush();
	} // end Write()
	
	public int Read(final byte[] p) throws Exception {
		final Field fieldDataInputStream = this.transport.getClass().getDeclaredField("dataInput");
		fieldDataInputStream.setAccessible(true);
		final DataInputStream dis = (DataInputStream)fieldDataInputStream.get(this.transport);
		return dis.read(p);
	} // end Read()
	
	public void createTransport() throws Exception {
		final Field fTransportFactory = JadbDevice.class.getDeclaredField("transportFactory");
		fTransportFactory.setAccessible(true);
		final Object objTransportFactory = fTransportFactory.get(this.device);
		final Method funcCreateTransport = objTransportFactory.getClass().getDeclaredMethod("createTransport");
		funcCreateTransport.setAccessible(true);
		this.transport = funcCreateTransport.invoke(objTransportFactory);
	} // end createTransport()
} // end class
