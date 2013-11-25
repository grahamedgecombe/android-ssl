package uk.ac.cam.gpe21.droidssl.mitm;

import com.sun.jna.LastErrorException;
import com.sun.jna.ptr.IntByReference;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

public final class Sockets {
	public static InetSocketAddress getOriginalDestination(Socket socket) throws IOException {
		int fd = FileDescriptors.getFd(socket);

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
