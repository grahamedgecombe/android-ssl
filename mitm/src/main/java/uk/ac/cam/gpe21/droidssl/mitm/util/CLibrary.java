/*
 * Copyright 2013-2014 Graham Edgecombe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.ac.cam.gpe21.droidssl.mitm.util;

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;

import java.util.Arrays;
import java.util.List;

public interface CLibrary extends Library {
	public final CLibrary INSTANCE = (CLibrary) Native.loadLibrary("c", CLibrary.class);

	/* from /usr/include/bits/socket.h */
	public final int PF_INET = 2;
	public final int PF_INET6 = 10;

	/* from /usr/include/bits/in.h */
	public final int SOL_IP = 0;
	public final int SOL_IPV6 = 41;
	public final int IP_TRANSPARENT = 19;

	/* from /usr/include/linux/netfilter_ipv4.h */
	public final int SO_ORIGINAL_DST = 80;

	/* from /usr/include/linux/netfilter_ipv6/ip6_tables.h */
	public final int IP6T_SO_ORIGINAL_DST = 80;

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

	/* from /usr/include/linux/in6.h */
	public final class sockaddr_in6 extends Structure {
		public short  sin6_family;
		public byte[] sin6_port     = new byte[2];
		public byte[] sin6_flowinfo = new byte[4];
		public byte[] sin6_addr     = new byte[16];
		public int    sin6_scope_id;

		@Override
		protected List getFieldOrder() {
			return Arrays.asList("sin6_family", "sin6_port", "sin6_flowinfo", "sin6_addr", "sin6_scope_id");
		}
	}

	/* from /usr/include/sys/socket.h */
	public int getsockopt(int socket, int level, int option_name, Pointer option_value, IntByReference option_len) throws LastErrorException;
	public int setsockopt(int socket, int level, int option_name, Pointer option_value, int option_len) throws LastErrorException;

	/* from /usr/include/string.h */
	public String strerror(int errnum);
}
