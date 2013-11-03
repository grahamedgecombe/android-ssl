package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.toolkits.exceptions.ThrowableSet;
import soot.toolkits.exceptions.UnitThrowAnalysis;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import uk.ac.cam.gpe21.droidssl.analysis.tag.VulnerabilityTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.Map;

public final class X509TrustManagerTransformer extends BodyTransformer {
	// TODO consider what to do with the getAcceptedIssuers/checkClientTrusted methods?

	@Override
	protected void internalTransform(Body body, String phase, Map<String, String> options) {
		SootMethod method = body.getMethod();

		SootClass clazz = method.getDeclaringClass();
		if (!clazz.getSuperclass().getType().equals(Types.X509_TRUST_MANAGER))
			return;

		if (!method.getName().equals("checkServerTrusted"))
			return;

		if (!Signatures.methodSignatureMatches(method, VoidType.v(), Types.X509_CERTIFICATE_ARRAY, Types.STRING))
			return;

		boolean anyExitThrowsException = false;

		UnitGraph graph = new ExceptionalUnitGraph(body);
		for (Unit unit : graph.getTails()) {
			ThrowableSet set = UnitThrowAnalysis.v().mightThrow(unit);
			if (set.catchableAs(Types.CERTIFICATE_EXCEPTION)) {
				anyExitThrowsException = true;
			}
		}

		if (!anyExitThrowsException) {
			clazz.addTag(new VulnerabilityTag());
			System.err.println("X509TrustManager " + clazz.getName() + " never throws CertificateException");
		}
	}
}
