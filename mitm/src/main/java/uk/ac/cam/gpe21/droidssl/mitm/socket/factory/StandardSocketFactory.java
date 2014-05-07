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

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public final class StandardSocketFactory extends SocketFactory {
	public StandardSocketFactory(SSLSocketFactory sslSocketFactory) {
		super(sslSocketFactory);
	}

	@Override
	public ServerSocket openServerSocket(InetSocketAddress address) throws IOException {
		ServerSocket socket = new ServerSocket();
		socket.bind(address);
		return socket;
	}

	@Override
	public Socket openSocket(InetSocketAddress source, InetSocketAddress destination) throws IOException {
		Socket socket = new Socket();
		socket.connect(destination);
		return socket;
	}
}
