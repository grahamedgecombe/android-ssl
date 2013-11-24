package uk.ac.cam.gpe21.droidssl.mitm;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

public interface CLibrary extends Library {
	final CLibrary INSTANCE = (CLibrary) Native.loadLibrary("c", CLibrary.class);

	final int PF_INET = 2;          /* from /usr/include/bits/socket.h */
	final int PF_INET6 = 10;

	final int SOL_IP = 0;           /* from /usr/include/bits/in.h */
	final int SO_ORIGINAL_DST = 80; /* from /usr/include/linux/netfilter_ipv4.h */

	int getsockopt(int s, int level, int optname, byte[] optval, IntByReference optlen);
}
