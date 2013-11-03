package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import uk.ac.cam.gpe21.droidssl.analysis.tag.VulnerabilityTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.FlowGraphUtils;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.Map;

public final class HttpClientHostnameVerifierTransformer extends BodyTransformer {
	@Override
	protected void internalTransform(Body body, String phase, Map<String, String> options) {
		SootMethod method = body.getMethod();

		SootClass clazz = method.getDeclaringClass();
		if (!clazz.getSuperclass().getType().equals(Types.ABSTRACT_VERIFIER))
			return;

		if (!method.getName().equals("verify"))
			return;

		if (!Signatures.methodSignatureMatches(method, VoidType.v(), Types.STRING, Types.STRING_ARRAY, Types.STRING_ARRAY))
			return;

		UnitGraph graph = new ExceptionalUnitGraph(body);
		if (!FlowGraphUtils.anyExitThrowsException(graph, Types.SSL_EXCEPTION)) {
			clazz.addTag(new VulnerabilityTag());
			System.err.println("AbstractVerifier " + clazz.getName() + " never throws SSLException");
		}
	}
}
