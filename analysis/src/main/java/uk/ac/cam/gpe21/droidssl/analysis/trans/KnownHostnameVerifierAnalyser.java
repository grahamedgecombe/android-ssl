package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.RefType;
import soot.Scene;
import soot.SootClass;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;
import uk.ac.cam.gpe21.droidssl.analysis.tag.HostnameVerifierTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.Set;

public final class KnownHostnameVerifierAnalyser extends Analyser {
	public KnownHostnameVerifierAnalyser(Set<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	private void tag(RefType ref, VulnerabilityState state) {
		SootClass clazz = Scene.v().getSootClass(ref.getClassName());
		clazz.addTag(new HostnameVerifierTag(state));
	}

	@Override
	public void analyse() {
		tag(Types.ALLOW_ALL_HOSTNAME_VERIFIER, VulnerabilityState.VULNERABLE);
		tag(Types.BROWSER_COMPAT_HOSTNAME_VERIFIER, VulnerabilityState.SAFE);
		tag(Types.STRICT_HOSTNAME_VERIFIER, VulnerabilityState.SAFE);
	}
}
