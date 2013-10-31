package uk.ac.cam.gpe21.droidssl.analysis;

import soot.*;
import soot.jimple.IntConstant;
import soot.jimple.ReturnStmt;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.Map;

public final class JsseHostnameVerifierTransformer extends BodyTransformer {
	@Override
	protected void internalTransform(Body body, String phase, Map<String, String> options) {
		SootMethod method = body.getMethod();

		SootClass clazz = method.getDeclaringClass();
		if (!clazz.implementsInterface(Types.HOSTNAME_VERIFIER.getClassName()))
			return;

		if (!Signatures.methodSignatureMatches(method, BooleanType.v(), "verify", Types.STRING, Types.SSL_SESSION))
			return;

		boolean allExitsReturnTrue = true;

		UnitGraph graph = new BriefUnitGraph(body);
		for (Unit unit : graph.getTails()) {
			if (unit instanceof ReturnStmt) {
				ReturnStmt stmt = (ReturnStmt) unit;
				if (!stmt.getOp().equals(IntConstant.v(1))) {
					allExitsReturnTrue = false;
				}
			}
		}

		if (allExitsReturnTrue) {
			System.err.println("HostnameVerifier " + clazz.getName() + " always returns true");
		}
	}
}
