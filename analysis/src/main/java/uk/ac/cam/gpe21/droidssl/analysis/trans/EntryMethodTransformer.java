package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;

import java.util.Map;

public final class EntryMethodTransformer extends SceneTransformer {
	@Override
	protected void internalTransform(String phase, Map<String, String> options) {
		for (SootClass clazz : Scene.v().getApplicationClasses()) {
			Scene.v().getEntryPoints().addAll(clazz.getMethods());
		}
	}
}
