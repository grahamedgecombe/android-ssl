package uk.ac.cam.gpe21.droidssl.analysis.trans;

import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;

import java.util.List;

public abstract class Analyser {
	protected final List<Vulnerability> vulnerabilities;

	public Analyser(List<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

	public abstract void analyse();
}
