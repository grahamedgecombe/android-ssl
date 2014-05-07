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

package uk.ac.cam.gpe21.droidssl.mitm.socket;

import java.io.IOException;
import java.net.*;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public final class WorkaroundNioServerSocket extends ServerSocket {
	private final ServerSocket socket;

	public WorkaroundNioServerSocket(ServerSocketChannel channel) throws IOException {
		this.socket = channel.socket();
	}

	@Override
	public Socket accept() throws IOException {
		/*
		 * Ensure accepted Sockets are wrapped in a WorkaroundNioSocket object
		 * before returning them.
		 */
		Socket client = socket.accept();
		SocketChannel ch = client.getChannel();
		if (ch != null) {
			return new WorkaroundNioSocket(ch);
		} else {
			throw new IllegalStateException();
		}
	}

	/* pass through every other method */
	@Override
	public void bind(SocketAddress endpoint) throws IOException {
		socket.bind(endpoint);
	}

	@Override
	public void bind(SocketAddress endpoint, int backlog) throws IOException {
		socket.bind(endpoint, backlog);
	}

	@Override
	public InetAddress getInetAddress() {
		return socket.getInetAddress();
	}

	@Override
	public int getLocalPort() {
		return socket.getLocalPort();
	}

	@Override
	public SocketAddress getLocalSocketAddress() {
		return socket.getLocalSocketAddress();
	}

	@Override
	public void close() throws IOException {
		socket.close();
	}

	@Override
	public ServerSocketChannel getChannel() {
		return socket.getChannel();
	}

	@Override
	public boolean isBound() {
		return socket.isBound();
	}

	@Override
	public boolean isClosed() {
		return socket.isClosed();
	}

	@Override
	public synchronized void setSoTimeout(int timeout) throws SocketException {
		socket.setSoTimeout(timeout);
	}

	@Override
	public synchronized int getSoTimeout() throws IOException {
		return socket.getSoTimeout();
	}

	@Override
	public void setReuseAddress(boolean on) throws SocketException {
		socket.setReuseAddress(on);
	}

	@Override
	public boolean getReuseAddress() throws SocketException {
		return socket.getReuseAddress();
	}

	@Override
	public String toString() {
		return socket.toString();
	}

	@Override
	public synchronized void setReceiveBufferSize(int size) throws SocketException {
		socket.setReceiveBufferSize(size);
	}

	@Override
	public synchronized int getReceiveBufferSize() throws SocketException {
		return socket.getReceiveBufferSize();
	}

	@Override
	public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
		socket.setPerformancePreferences(connectionTime, latency, bandwidth);
	}
}
