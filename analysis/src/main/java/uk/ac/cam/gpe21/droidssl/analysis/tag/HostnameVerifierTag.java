package uk.ac.cam.gpe21.droidssl.analysis.tag;

import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;

public final class HostnameVerifierTag extends VulnerabilityTag {
	public static final String NAME = "hostname_verifier";

	public HostnameVerifierTag(VulnerabilityState state) {
		super(NAME, state);
	}
}
