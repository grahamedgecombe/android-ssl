package uk.ac.cam.gpe21.droidssl.mitm.util;

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;

import java.util.Arrays;
import java.util.List;

public interface CLibrary extends Library {
	public final CLibrary INSTANCE = (CLibrary) Native.loadLibrary("c", CLibrary.class);

	/* from /usr/include/bits/socket.h */
	public final int PF_INET = 2;

	/* from /usr/include/bits/in.h */
	public final int SOL_IP = 0;
	public final int IP_TRANSPARENT = 19;

	/* from /usr/include/linux/netfilter_ipv4.h */
	public final int SO_ORIGINAL_DST = 80;

	/* from /usr/include/linux/in.h */
	public final class sockaddr_in extends Structure {
		public short sin_family;
		public byte[] sin_port = new byte[2];
		public byte[] sin_addr = new byte[4];
		public byte[] sin_zero = new byte[8];

		@Override
		protected List getFieldOrder() {
			return Arrays.asList("sin_family", "sin_port", "sin_addr", "sin_zero");
		}
	}

	/* from /usr/include/sys/socket.h */
	public int getsockopt(int socket, int level, int option_name, Pointer option_value, IntByReference option_len) throws LastErrorException;
	public int setsockopt(int socket, int level, int option_name, Pointer option_value, int option_len) throws LastErrorException;

	/* from /usr/include/string.h */
	public String strerror(int errnum);
}
