package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.Body;
import soot.BodyTransformer;
import soot.SootClass;
import soot.SootMethod;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;

import java.util.List;
import java.util.Map;

public abstract class Analyser extends BodyTransformer {
	protected final List<Vulnerability> vulnerabilities;

	public Analyser(List<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

	@Override
	protected final void internalTransform(Body body, String phase, Map<String, String> options) {
		SootMethod method = body.getMethod();
		SootClass clazz = method.getDeclaringClass();
		analyse(clazz, method, body);
	}

	protected abstract void analyse(SootClass clazz, SootMethod method, Body body);
}
