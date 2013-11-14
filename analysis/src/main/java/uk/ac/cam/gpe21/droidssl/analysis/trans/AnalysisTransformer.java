package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.SceneTransformer;

import java.util.Map;

public final class AnalysisTransformer extends SceneTransformer {
	private final Analyser[] analysers;

	public AnalysisTransformer(Analyser... analysers) {
		this.analysers = analysers;
	}

	@Override
	protected void internalTransform(String phase, Map<String, String> options) {
		for (Analyser analyser : analysers) {
			analyser.analyse();
		}
	}
}
