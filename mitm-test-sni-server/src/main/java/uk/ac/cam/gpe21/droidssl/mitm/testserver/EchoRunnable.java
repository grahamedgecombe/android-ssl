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

package uk.ac.cam.gpe21.droidssl.mitm.testserver;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class EchoRunnable implements Runnable {
	private final SSLSocket socket;

	public EchoRunnable(SSLSocket socket) {
		this.socket = socket;
	}

	@Override
	public void run() {
		try (InputStream is = socket.getInputStream();
			 OutputStream os = socket.getOutputStream()) {
			byte[] buf = new byte[4096];
			int len;
			while ((len = is.read(buf, 0, buf.length)) != -1) {
				os.write(buf, 0, len);
			}
		} catch (IOException ex) {
			/* ignore (thread will terminate automatically) */
		}
	}
}
