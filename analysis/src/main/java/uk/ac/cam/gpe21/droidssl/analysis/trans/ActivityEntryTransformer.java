package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.Map;

public final class ActivityEntryTransformer extends SceneTransformer {
	@Override
	protected void internalTransform(String phase, Map<String, String> options) {
		for (SootClass clazz : Scene.v().getApplicationClasses()) {
			if (clazz.getSuperclass().getType().equals(Types.ACTIVITY)) {
				for (SootMethod method : clazz.getMethods()) {
					if (method.isStatic())
						continue;

					if (!method.getReturnType().equals(VoidType.v()))
						continue;

					if (method.getParameterCount() != 1)
						continue;

					if (!method.getParameterType(0).equals(Types.VIEW))
						continue;

					Scene.v().getEntryPoints().add(method);
				}
			}
		}
	}
}
