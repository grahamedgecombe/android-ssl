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

import org.junit.Test;

import java.net.InetSocketAddress;

import static org.junit.Assert.assertEquals;

public final class SocketAddressParserTest {
	@Test
	public void testIpv4() {
		InetSocketAddress address = SocketAddressParser.parse("198.51.100.1:443");
		assertEquals(new InetSocketAddress("198.51.100.1", 443), address);
	}

	@Test
	public void testIpv6() {
		InetSocketAddress address = SocketAddressParser.parse("[2001:DB8::1]:443");
		assertEquals(new InetSocketAddress("2001:DB8::1", 443), address);
	}

	@Test
	public void testHostname() {
		InetSocketAddress address = SocketAddressParser.parse("example.com:443");
		assertEquals(new InetSocketAddress("example.com", 443), address);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testIpv4WithoutPort() {
		SocketAddressParser.parse("198.51.100.1");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testIpv6WithoutPort() {
		SocketAddressParser.parse("[2001:DB8::1]");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testHostnameWithoutPort() {
		SocketAddressParser.parse("example.com");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidPort() {
		SocketAddressParser.parse("198.51.100.1:hello");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testMultipleColons() {
		SocketAddressParser.parse("example.com:a:b");
	}
}
