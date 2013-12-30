package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.SceneTransformer;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;

import java.util.Map;
import java.util.Set;

public final class AnalysisTransformer extends SceneTransformer {
	private final Set<Vulnerability> vulnerabilities;
	private final Analyser[] analysers;

	public AnalysisTransformer(Set<Vulnerability> vulnerabilities, Analyser... analysers) {
		this.vulnerabilities = vulnerabilities;
		this.analysers = analysers;
	}

	@Override
	protected void internalTransform(String phase, Map<String, String> options) {
		int size;
		do {
			size = vulnerabilities.size();
			for (Analyser analyser : analysers) {
				analyser.analyse();
			}
		} while (size != vulnerabilities.size());
	}
}
