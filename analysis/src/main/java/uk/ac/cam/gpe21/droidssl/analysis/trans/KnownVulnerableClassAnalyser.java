package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.Scene;
import soot.SootClass;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;
import uk.ac.cam.gpe21.droidssl.analysis.tag.HostnameVerifierTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.List;

public final class KnownVulnerableClassAnalyser extends Analyser {
	public KnownVulnerableClassAnalyser(List<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	public void analyse() {
		SootClass clazz = Scene.v().getSootClass(Types.ALLOW_ALL_HOSTNAME_VERIFIER.getClassName());
		clazz.addTag(new HostnameVerifierTag(VulnerabilityState.VULNERABLE));
	}
}
