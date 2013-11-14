package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.Body;
import soot.SootClass;
import soot.SootMethod;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;
import uk.ac.cam.gpe21.droidssl.analysis.tag.HostnameVerifierTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.List;

public final class KnownVulnerableClassAnalyser extends IntraProceduralAnalyser {
	public KnownVulnerableClassAnalyser(List<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	protected void analyse(SootClass clazz, SootMethod method, Body body) {
		if (clazz.getType().equals(Types.ALLOW_ALL_HOSTNAME_VERIFIER)) {
			clazz.addTag(new HostnameVerifierTag(VulnerabilityState.VULNERABLE));
		}
	}
}
