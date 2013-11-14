package uk.ac.cam.gpe21.droidssl.analysis.tag;

import soot.tagkit.Tag;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;

public final class HostnameVerifierTag implements Tag {
	public static final String NAME = "hostname_verifier";

	private final VulnerabilityState state;

	public HostnameVerifierTag(VulnerabilityState state) {
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
