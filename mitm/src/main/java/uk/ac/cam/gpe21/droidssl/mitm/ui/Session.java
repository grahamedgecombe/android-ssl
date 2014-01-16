package uk.ac.cam.gpe21.droidssl.mitm.ui;

import java.awt.*;
import java.net.InetSocketAddress;

public final class Session {
	public enum State {
		OPEN(Color.GREEN, "Open"),
		CLOSED(Color.GRAY, "Closed"),
		FAILED(Color.RED, "Failed");

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

	public State getState() {
		return state;
	}

	public void setState(State state) {
		this.state = state;
	}

	public Throwable getFailureReason() {
		return failureReason;
	}

	public void setFailureReason(Throwable failureReason) {
		this.failureReason = failureReason;
	}

	@Override
	public String toString() {
		return destination.getHostName() + ":" + destination.getPort();
	}
}
