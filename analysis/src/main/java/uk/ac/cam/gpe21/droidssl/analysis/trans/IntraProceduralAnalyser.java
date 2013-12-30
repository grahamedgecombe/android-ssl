package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.Body;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;

import java.util.Set;

public abstract class IntraProceduralAnalyser extends Analyser {
	public IntraProceduralAnalyser(Set<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	public void analyse() {
		for (SootClass clazz : Scene.v().getApplicationClasses()) {
			for (SootMethod method : clazz.getMethods()) {
				if (!method.isConcrete())
					continue;

				Body body = method.retrieveActiveBody();
				analyse(clazz, method, body);
			}
		}
	}

	protected abstract void analyse(SootClass clazz, SootMethod method, Body body);
}
