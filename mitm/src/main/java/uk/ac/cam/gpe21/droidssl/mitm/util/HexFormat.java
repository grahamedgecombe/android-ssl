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

public final class HexFormat {
	private static String toHex(int num, int pad) {
		String str = Integer.toHexString(num);
		while (str.length() < pad)
			str = '0' + str;
		return str;
	}

	public static String format(byte[] array, int len) {
		StringBuilder buf = new StringBuilder();

		int lines = (len + 15) / 16;
		for (int i = 0; i < lines; i++) {
			/* offset */
			int off = i * 16;
			buf.append(toHex(off, 4));
			buf.append("  ");

			/* bytes in hex */
			int bytes = Math.min(16, len - off);
			int j;
			for (j = 0; j < bytes; j++) {
				if (j == 8)
					buf.append(' '); /* extra space halfway through */

				buf.append(toHex(array[off + j] & 0xff, 2));
				buf.append(' ');
			}
			for (; j < 16; j++) {
				if (j == 8)
					buf.append(' ');

				buf.append("   ");
			}

			buf.append("  ");

			/* bytes in ASCII */
			for (j = 0; j < bytes; j++) {
				if (j == 8)
					buf.append(' ');

				int c = array[off + j] & 0xff;
				if (c >= 32 && c < 126) {
					buf.append((char) c);
				} else {
					buf.append('.');
				}
			}

			/* new line */
			if (i != (lines - 1))
				buf.append('\n');
		}

		return buf.toString();
	}

	private HexFormat() {
		/* to prevent instantiation */
	}
}
