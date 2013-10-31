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

				if (!method.getDeclaringClass().getName().equals(Types.HTTPS_URL_CONNECTION.getClassName()))
					continue;

				if (!Signatures.methodSignatureMatches(method, VoidType.v(), "setDefaultHostnameVerifier", Types.HOSTNAME_VERIFIER))
					continue;

				if (!method.isStatic())
					continue;

				List<ValueBox> list = stmt.getInvokeExpr().getUseBoxes();
				// TODO check list size==1 & element is instanceof Local
				Local local = (Local) list.get(0).getValue();

				PointsToSet set = Scene.v().getPointsToAnalysis().reachingObjects(local);
				// TODO check if the hostname verifier is a known 'bad' one
			}
		}
	}
}
