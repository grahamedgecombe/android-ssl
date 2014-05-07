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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;

public final class WorkaroundNioSocket extends Socket {
	private final Socket socket;

	public WorkaroundNioSocket(SocketChannel channel) {
		this.socket = channel.socket();
	}

	@Override
	public OutputStream getOutputStream() throws IOException {
		/*
		 * Workaround a bug:
		 *   http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4509080
		 *   http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4774871
		 *   http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6977788
		 *
		 * If a Socket is backed by a SocketChannel (via SocketChannel's
		 * socket() method), both the InputStream and OutputStream it returns
		 * synchronize on the same lock, making a concurrent read()/write()
		 * impossible - e.g. consider the following case:
		 *
		 * - server is waiting for data
		 * - client starts read()
		 * - client starts write() but blocks because read() hold the lock
		 * - server never receives the data, thus never sends a response,
		 *   meaning read() continues to block indefinitely
		 *
		 * The lock both streams synchronize on is the SelectableChannel's
		 * blockingLock(). As a workaround, we wrap the SelectableChannel
		 * within a WritableByteChannel, and use that to create the
		 * OutputStream instead, which does not trigger the faulty locking.
		 *
		 * (There is no need to do the same to the InputStream - it does not
		 * matter if it holds the lock or not after the workaround. Equally, we
		 * could have wrapped the InputStream and left the original
		 * OutputStream. However, using the OutputStream is easier as
		 * sun.nio.ch.SocketAdaptor calls Channels.newOutputStream() directly,
		 * whereas it has its own custom SocketInputStream implementation.)
		 */
		final SocketChannel ch = socket.getChannel();
		if (ch != null) {
			return Channels.newOutputStream(new WritableByteChannel() {
				@Override
				public int write(ByteBuffer src) throws IOException {
					return ch.write(src);
				}

				@Override
				public boolean isOpen() {
					return ch.isOpen();
				}

				@Override
				public void close() throws IOException {
					ch.close();
				}
			});
		} else {
			throw new IllegalStateException();
		}
	}

	/* pass through every other method */
	@Override
	public void connect(SocketAddress endpoint) throws IOException {
		socket.connect(endpoint);
	}

	@Override
	public void connect(SocketAddress endpoint, int timeout) throws IOException {
		socket.connect(endpoint, timeout);
	}

	@Override
	public void bind(SocketAddress bindpoint) throws IOException {
		socket.bind(bindpoint);
	}

	@Override
	public InetAddress getInetAddress() {
		return socket.getInetAddress();
	}

	@Override
	public InetAddress getLocalAddress() {
		return socket.getLocalAddress();
	}

	@Override
	public int getPort() {
		return socket.getPort();
	}

	@Override
	public int getLocalPort() {
		return socket.getLocalPort();
	}

	@Override
	public SocketAddress getRemoteSocketAddress() {
		return socket.getRemoteSocketAddress();
	}

	@Override
	public SocketAddress getLocalSocketAddress() {
		return socket.getLocalSocketAddress();
	}

	@Override
	public SocketChannel getChannel() {
		return socket.getChannel();
	}

	@Override
	public InputStream getInputStream() throws IOException {
		return socket.getInputStream();
	}

	@Override
	public void setTcpNoDelay(boolean on) throws SocketException {
		socket.setTcpNoDelay(on);
	}

	@Override
	public boolean getTcpNoDelay() throws SocketException {
		return socket.getTcpNoDelay();
	}

	@Override
	public void setSoLinger(boolean on, int linger) throws SocketException {
		socket.setSoLinger(on, linger);
	}

	@Override
	public int getSoLinger() throws SocketException {
		return socket.getSoLinger();
	}

	@Override
	public void sendUrgentData(int data) throws IOException {
		socket.sendUrgentData(data);
	}

	@Override
	public void setOOBInline(boolean on) throws SocketException {
		socket.setOOBInline(on);
	}

	@Override
	public boolean getOOBInline() throws SocketException {
		return socket.getOOBInline();
	}

	@Override
	public synchronized void setSoTimeout(int timeout) throws SocketException {
		socket.setSoTimeout(timeout);
	}

	@Override
	public synchronized int getSoTimeout() throws SocketException {
		return socket.getSoTimeout();
	}

	@Override
	public synchronized void setSendBufferSize(int size) throws SocketException {
		socket.setSendBufferSize(size);
	}

	@Override
	public synchronized int getSendBufferSize() throws SocketException {
		return socket.getSendBufferSize();
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
	public void setKeepAlive(boolean on) throws SocketException {
		socket.setKeepAlive(on);
	}

	@Override
	public boolean getKeepAlive() throws SocketException {
		return socket.getKeepAlive();
	}

	@Override
	public void setTrafficClass(int tc) throws SocketException {
		socket.setTrafficClass(tc);
	}

	@Override
	public int getTrafficClass() throws SocketException {
		return socket.getTrafficClass();
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
	public synchronized void close() throws IOException {
		socket.close();
	}

	@Override
	public void shutdownInput() throws IOException {
		socket.shutdownInput();
	}

	@Override
	public void shutdownOutput() throws IOException {
		socket.shutdownOutput();
	}

	@Override
	public String toString() {
		return socket.toString();
	}

	@Override
	public boolean isConnected() {
		return socket.isConnected();
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
	public boolean isInputShutdown() {
		return socket.isInputShutdown();
	}

	@Override
	public boolean isOutputShutdown() {
		return socket.isOutputShutdown();
	}

	@Override
	public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
		socket.setPerformancePreferences(connectionTime, latency, bandwidth);
	}
}
