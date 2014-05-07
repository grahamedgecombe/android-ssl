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

package uk.ac.cam.gpe21.droidssl.mitm.ui;

import uk.ac.cam.gpe21.droidssl.mitm.crypto.cert.CertificateKey;

import java.awt.*;
import java.net.InetSocketAddress;

public final class Session {
	public enum State {
		OPEN(Color.GREEN, "Open"),
		CLOSED(Color.GRAY, "Closed"),
		FAILED(Color.RED, "Failed"),
		MAYBE_FAILED(Color.ORANGE, "Maybe Failed"); /* means connection closed without sending data */

		private final Color color;
		private final String description;

		private State(Color color, String description) {
			this.color = color;
			this.description = description;
		}

		public Color getColor() {
			return color;
		}

		@Override
		public String toString() {
			return description;
		}
	}

	private final InetSocketAddress source, destination;
	private State state = State.OPEN;
	private Throwable failureReason;
	private CertificateKey realKey, key;
	private String cipherSuite;
	private String protocol;

	public Session(InetSocketAddress source, InetSocketAddress destination) {
		this.source = source;
		this.destination = destination;
	}

	public InetSocketAddress getSource() {
		return source;
	}

	public InetSocketAddress getDestination() {
		return destination;
	}

	public boolean isSsl() {
		return key != null;
	}

	public CertificateKey getRealKey() {
		return realKey;
	}

	public void setRealKey(CertificateKey realKey) {
		this.realKey = realKey;
	}

	public CertificateKey getKey() {
		return key;
	}

	public void setKey(CertificateKey key) {
		this.key = key;
	}

	public String getCipherSuite() {
		return cipherSuite;
	}

	public void setCipherSuite(String cipherSuite) {
		this.cipherSuite = cipherSuite;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public State getState() {
		synchronized (this) {
			return state;
		}
	}

	public void setState(State state) {
		synchronized (this) {
			/*
			 * Only allow open->closed or open->failed transitions (or the fact
			 * two threads run I/O can cause e.g. a failed to connection to
			 * transition to closed, which stops the GUI from displaying the
			 * exception).
			 */
			if (this.state != State.OPEN)
				return;

			this.state = state;
		}
	}

	public Throwable getFailureReason() {
		synchronized (this) {
			return failureReason;
		}
	}

	public void setFailureReason(Throwable failureReason) {
		synchronized (this) {
			this.failureReason = failureReason;
		}
	}

	@Override
	public String toString() {
		return destination.getHostName() + ":" + destination.getPort();
	}
}
