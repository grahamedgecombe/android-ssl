package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.Body;
import soot.SootClass;
import soot.SootMethod;
import soot.VoidType;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityType;
import uk.ac.cam.gpe21.droidssl.analysis.tag.TrustManagerTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.FlowGraphUtils;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.List;

public final class TrustManagerAnalyser extends IntraProceduralAnalyser {
	public TrustManagerAnalyser(List<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	// TODO consider what to do with the getAcceptedIssuers/checkClientTrusted methods?
	@Override
	protected void analyse(SootClass clazz, SootMethod method, Body body) {
		if (!clazz.implementsInterface(Types.X509_TRUST_MANAGER.getClassName()))
			return;

		if (!method.getName().equals("checkServerTrusted"))
			return;

		if (!Signatures.methodSignatureMatches(method, VoidType.v(), Types.X509_CERTIFICATE_ARRAY, Types.STRING))
			return;

		VulnerabilityState state = VulnerabilityState.UNKNOWN;

		UnitGraph graph = new ExceptionalUnitGraph(body);
		if (!FlowGraphUtils.anyExitThrowsException(graph, Types.CERTIFICATE_EXCEPTION)) {
			state = VulnerabilityState.VULNERABLE;
		}

		clazz.addTag(new TrustManagerTag(state));
		vulnerabilities.add(new Vulnerability(clazz, VulnerabilityType.PERMISSIVE_TRUST_MANAGER, state));
	}
}
