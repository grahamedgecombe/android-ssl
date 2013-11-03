package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityType;
import uk.ac.cam.gpe21.droidssl.analysis.tag.VulnerabilityTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.FlowGraphUtils;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.List;
import java.util.Map;

public final class JsseHostnameVerifierTransformer extends BodyTransformer {
	private final List<Vulnerability> vulnerabilities;

	public JsseHostnameVerifierTransformer(List<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

	@Override
	protected void internalTransform(Body body, String phase, Map<String, String> options) {
		SootMethod method = body.getMethod();

		SootClass clazz = method.getDeclaringClass();
		if (!clazz.implementsInterface(Types.HOSTNAME_VERIFIER.getClassName()))
			return;

		if (!method.getName().equals("verify"))
			return;

		if (!Signatures.methodSignatureMatches(method, BooleanType.v(), Types.STRING, Types.SSL_SESSION))
			return;

		UnitGraph graph = new BriefUnitGraph(body);
		if (FlowGraphUtils.allExitsReturnTrue(graph)) {
			clazz.addTag(new VulnerabilityTag());
			vulnerabilities.add(new Vulnerability(clazz, VulnerabilityType.PERMISSIVE_HOSTNAME_VERIFIER));
		}
	}
}
