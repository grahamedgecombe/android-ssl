package uk.ac.cam.gpe21.droidssl.analysis.trans;

import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;

import java.util.Set;

public abstract class Analyser {
	protected final Set<Vulnerability> vulnerabilities;

	public Analyser(Set<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

	public abstract void analyse();
}
