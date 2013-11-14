package uk.ac.cam.gpe21.droidssl.analysis.tag;

import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;

public final class TrustManagerTag extends VulnerabilityTag {
	public static final String NAME = "trust_manager";

	public TrustManagerTag(VulnerabilityState state) {
		super(NAME, state);
	}
}
