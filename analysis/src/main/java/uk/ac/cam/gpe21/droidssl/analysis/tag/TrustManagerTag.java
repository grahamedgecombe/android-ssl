package uk.ac.cam.gpe21.droidssl.analysis.tag;

import soot.tagkit.Tag;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;

public final class TrustManagerTag implements Tag { // TODO merge with HostnameVerifierTag somehow? (abstract base class?)
	public static final String NAME = "trust_manager";

	private final VulnerabilityState state;

	public TrustManagerTag(VulnerabilityState state) {
		this.state = state;
	}

	public VulnerabilityState getState() {
		return state;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public byte[] getValue() {
		return new byte[] {
			(byte) state.ordinal()
		};
	}
}
