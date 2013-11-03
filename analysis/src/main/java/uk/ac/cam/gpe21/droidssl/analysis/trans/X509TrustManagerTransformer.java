package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityType;
import uk.ac.cam.gpe21.droidssl.analysis.tag.VulnerabilityTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.FlowGraphUtils;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.List;
import java.util.Map;

public final class X509TrustManagerTransformer extends BodyTransformer {
	private final List<Vulnerability> vulnerabilities;

	public X509TrustManagerTransformer(List<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

	// TODO consider what to do with the getAcceptedIssuers/checkClientTrusted methods?
	@Override
	protected void internalTransform(Body body, String phase, Map<String, String> options) {
		SootMethod method = body.getMethod();

		SootClass clazz = method.getDeclaringClass();
		if (!clazz.implementsInterface(Types.X509_TRUST_MANAGER.getClassName()))
			return;

		if (!method.getName().equals("checkServerTrusted"))
			return;

		if (!Signatures.methodSignatureMatches(method, VoidType.v(), Types.X509_CERTIFICATE_ARRAY, Types.STRING))
			return;

		UnitGraph graph = new ExceptionalUnitGraph(body);
		if (!FlowGraphUtils.anyExitThrowsException(graph, Types.CERTIFICATE_EXCEPTION)) {
			clazz.addTag(new VulnerabilityTag());
			vulnerabilities.add(new Vulnerability(clazz, VulnerabilityType.PERMISSIVE_TRUST_MANAGER));
		}
	}
}
