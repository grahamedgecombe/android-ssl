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

import static org.junit.Assert.assertEquals;

public final class HexFormatTest {
	@Test
	public void testEmpty() {
		byte[] array = new byte[0];
		String str = HexFormat.format(array, array.length);
		assertEquals("", str);
	}

	@Test
	public void testShortLine() {
		byte[] array = "hello".getBytes();
		String str = HexFormat.format(array, array.length);
		assertEquals("0000  68 65 6c 6c 6f                                     hello", str);
	}

	@Test
	public void testLongLine() {
		byte[] array = "hello world".getBytes();
		String str = HexFormat.format(array, array.length);
		assertEquals("0000  68 65 6c 6c 6f 20 77 6f  72 6c 64                  hello wo rld", str);
	}

	@Test
	public void testMultipleLines() {
		byte[] array = "The quick brown fox jumped over the lazy dog.".getBytes();
		String str = HexFormat.format(array, array.length);
		assertEquals(
			"0000  54 68 65 20 71 75 69 63  6b 20 62 72 6f 77 6e 20   The quic k brown \n" +
			"0010  66 6f 78 20 6a 75 6d 70  65 64 20 6f 76 65 72 20   fox jump ed over \n" +
			"0020  74 68 65 20 6c 61 7a 79  20 64 6f 67 2e            the lazy  dog.", str);
	}
}
