package uk.ac.cam.gpe21.droidssl.analysis;

import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.Map;

public final class KnownVulnerableClassTagger extends SceneTransformer {
	@Override
	protected void internalTransform(String phase, Map<String, String> options) {
		for (SootClass clazz : Scene.v().getClasses()) {
			if (clazz.getType().equals(Types.ALLOW_ALL_HOSTNAME_VERIFIER)) {
				clazz.addTag(new VulnerabilityTag());
			}
		}
	}
}
