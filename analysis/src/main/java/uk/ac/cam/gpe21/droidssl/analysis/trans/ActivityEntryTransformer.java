package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.Map;

public final class ActivityEntryTransformer extends SceneTransformer {
	@Override
	protected void internalTransform(String phase, Map<String, String> options) {
		for (SootClass clazz : Scene.v().getApplicationClasses()) {
			if (clazz.getSuperclass().getType().equals(Types.ACTIVITY)) {
				for (SootMethod method : clazz.getMethods()) {
					if (Signatures.methodSignatureMatches(method, VoidType.v(), Types.VIEW) && !method.isStatic()) {
						Scene.v().getEntryPoints().add(method);
					}
				}
			}
		}
	}
}
