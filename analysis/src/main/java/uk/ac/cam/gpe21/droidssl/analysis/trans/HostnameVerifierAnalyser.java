package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.Body;
import soot.BooleanType;
import soot.SootClass;
import soot.SootMethod;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityType;
import uk.ac.cam.gpe21.droidssl.analysis.tag.HostnameVerifierTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.FlowGraphUtils;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.Set;

public final class HostnameVerifierAnalyser extends IntraProceduralAnalyser {
	public HostnameVerifierAnalyser(Set<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	protected void analyse(SootClass clazz, SootMethod method, Body body) {
		if (!clazz.implementsInterface(Types.HOSTNAME_VERIFIER.getClassName()))
			return;

		if (!Signatures.methodSignatureMatches(method, BooleanType.v(), "verify", Types.STRING, Types.SSL_SESSION))
			return;

		VulnerabilityState state = VulnerabilityState.UNKNOWN;

		UnitGraph graph = new BriefUnitGraph(body);
		if (FlowGraphUtils.allExitsReturnTrue(graph)) {
			state = VulnerabilityState.VULNERABLE;
		}

		clazz.addTag(new HostnameVerifierTag(state));
		vulnerabilities.add(new Vulnerability(clazz, VulnerabilityType.PERMISSIVE_HOSTNAME_VERIFIER, state));
	}
}
