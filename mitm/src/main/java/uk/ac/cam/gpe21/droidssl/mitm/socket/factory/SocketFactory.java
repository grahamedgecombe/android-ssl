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

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public abstract class SocketFactory {
	private final SSLSocketFactory sslSocketFactory;

	public SocketFactory(SSLSocketFactory sslSocketFactory) {
		this.sslSocketFactory = sslSocketFactory;
	}

	public abstract ServerSocket openServerSocket(InetSocketAddress address) throws IOException;
	public abstract Socket openSocket(InetSocketAddress source, InetSocketAddress destination) throws IOException;

	public final SSLSocket openSslSocket(InetSocketAddress source, InetSocketAddress destination) throws IOException {
		return openSslSocket(source, destination, destination.getAddress().getHostAddress());
	}

	public final SSLSocket openSslSocket(InetSocketAddress source, InetSocketAddress destination, String host) throws IOException {
		Socket raw = openSocket(source, destination);
		return (SSLSocket) sslSocketFactory.createSocket(raw, host, destination.getPort(), true);
	}
}
