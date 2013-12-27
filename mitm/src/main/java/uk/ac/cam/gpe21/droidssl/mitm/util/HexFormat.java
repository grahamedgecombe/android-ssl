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
