package uk.ac.cam.gpe21.droidssl.mitm.util;

import com.sun.jna.LastErrorException;
import com.sun.jna.ptr.IntByReference;

import javax.net.ssl.SSLSocket;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

public final class Sockets {
	private static final Class<?> SSL_SOCKET_IMPL;
	private static final Field SOCK_INPUT;
	private static final Field FD;

	static {
		try {
			SSL_SOCKET_IMPL = Class.forName("sun.security.ssl.SSLSocketImpl");

			SOCK_INPUT = Sockets.SSL_SOCKET_IMPL.getDeclaredField("sockInput");
			SOCK_INPUT.setAccessible(true);

			FD = FileDescriptor.class.getDeclaredField("fd");
			FD.setAccessible(true);
		} catch (NoSuchFieldException | ClassNotFoundException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	public static int getFileDescriptor(Socket socket) throws IOException {
		try {
			Object in;
			if (socket instanceof SSLSocket) {
				/*
				 * Socket.getInputStream() on an SSLSocket returns the
				 * InputStream which reads the decrypted data from a buffer in
				 * memory - in this case, we read the private
				 * SSLSocketImpl.sockInput field with reflection to get at the
				 * InputStream which is backed by a file descriptor.
				 */
				in = SOCK_INPUT.get(socket);
			} else {
				in = socket.getInputStream();
			}

			if (!(in instanceof FileInputStream))
				throw new IOException("sockInput is not an instance of FileInputStream");

			FileInputStream fin = (FileInputStream) in;
			FileDescriptor fd = fin.getFD();

			return FD.getInt(fd);
		} catch (IllegalAccessException ex) {
			throw new IOException(ex);
		}
	}

	public static InetSocketAddress getOriginalDestination(Socket socket) throws IOException {
		int fd = getFileDescriptor(socket);

		CLibrary.sockaddr_in addr = new CLibrary.sockaddr_in();
		try {
			IntByReference len = new IntByReference(addr.size());
			CLibrary.INSTANCE.getsockopt(fd, CLibrary.SOL_IP, CLibrary.SO_ORIGINAL_DST, addr.getPointer(), len);

			/*
			 * This call is required to copy the values from the native memory
			 * backing the struct into the fields of the Java object.
			 */
			addr.read();
		} catch (LastErrorException ex) {
			throw new IOException("getsockopt: " + CLibrary.INSTANCE.strerror(ex.getErrorCode()));
		}

		if (addr.sin_family == CLibrary.PF_INET) {
			/*
			 * JNA takes care of reversing the order of the bytes in integer
			 * struct fields. However, sin_port is already in network byte
			 * order (big endian), the same byte order as used by Java, so JNA
			 * actually converts sin_port to little endian. Therefore we need to
			 * call Short.reverseBytes() to swap it back to big endian.
			 *
			 * TODO if the underlying CPU is big endian, do we need to call
			 * reverseBytes()?
			 */
			int port = Short.reverseBytes(addr.sin_port) & 0xFFFF;
			InetAddress ip = InetAddress.getByAddress(addr.sin_addr);
			return new InetSocketAddress(ip, port);
		} else {
			throw new IOException("Unknown protocol family (expected PF_INET): " + addr.sin_family);
		}
	}

	private Sockets() {
		/* to prevent instantiation */
	}
}
