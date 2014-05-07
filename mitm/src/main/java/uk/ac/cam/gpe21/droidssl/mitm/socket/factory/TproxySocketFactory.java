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

package uk.ac.cam.gpe21.droidssl.mitm.socket.factory;

import uk.ac.cam.gpe21.droidssl.mitm.socket.SocketUtils;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public final class TproxySocketFactory extends SocketFactory {
	public TproxySocketFactory(SSLSocketFactory sslSocketFactory) {
		super(sslSocketFactory);
	}

	@Override
	public ServerSocket openServerSocket(InetSocketAddress address) throws IOException {
		ServerSocket socket = SocketUtils.openTproxyServerSocket();
		socket.bind(address);
		return socket;
	}

	@Override
	public Socket openSocket(InetSocketAddress source, InetSocketAddress destination) throws IOException {
		Socket socket = SocketUtils.openTproxySocket();

		/*
		 * We open two connections in quick succession (the first is to detect
		 * the use of SSL, the second is the actual connection that will be
		 * used for the rest of the MITM.) Therefore we need to enable
		 * SO_REUSEADDR to stop bind() from failing with the same source
		 * address in TPROXY mode.
		 */
		socket.setReuseAddress(true);

		socket.bind(source);
		socket.connect(destination);
		return socket;
	}
}
