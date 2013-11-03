package uk.ac.cam.gpe21.droidssl.analysis;

import soot.*;
import soot.jimple.InvokeStmt;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.List;
import java.util.Map;

public final class DefaultJsseHostnameVerifierTransformer extends BodyTransformer {
	@Override
	protected void internalTransform(Body body, String phase, Map<String, String> options) {
		for (Unit unit : body.getUnits()) {
			if (unit instanceof InvokeStmt) {
				InvokeStmt stmt = (InvokeStmt) unit;
				SootMethod method = stmt.getInvokeExpr().getMethod();

				if (!method.getDeclaringClass().getType().equals(Types.HTTPS_URL_CONNECTION))
					continue;

				if (!Signatures.methodSignatureMatches(method, VoidType.v(), "setDefaultHostnameVerifier", Types.HOSTNAME_VERIFIER))
					continue;

				if (!method.isStatic())
					continue;

				List<ValueBox> list = stmt.getInvokeExpr().getUseBoxes();
				if (list.size() != 1)
					continue; /* TODO could this ever happen? */

				Value value = list.get(0).getValue();
				if (!(value instanceof Local))
					continue; /* TODO could this ever happen? */

				Local local = (Local) value;

				PointsToSet set = Scene.v().getPointsToAnalysis().reachingObjects(local);
				for (Type type : set.possibleTypes()) {
					if (!(type instanceof RefType))
						continue;

					RefType ref = (RefType) type;
					if (ref.getSootClass().hasTag(VulnerabilityTag.NAME)) {
						System.err.println("Method " + body.getMethod().getDeclaringClass().getName() + "::" + body.getMethod().getName() + " sets default hostname verifier to known bad verifier " + ref.getClassName());
					}
				}
			}
		}
	}
}
