package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityType;
import uk.ac.cam.gpe21.droidssl.analysis.tag.HostnameVerifierTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.List;

public final class HttpsUrlConnectionAnalyser extends IntraProceduralAnalyser {
	public HttpsUrlConnectionAnalyser(List<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	protected void analyse(SootClass clazz, final SootMethod method, Body body) {
		for (Unit unit : body.getUnits()) {
			unit.apply(new AbstractStmtSwitch() {
				@Override
				public void caseInvokeStmt(InvokeStmt stmt) {
					InvokeExpr expr = stmt.getInvokeExpr();
					if (!(expr instanceof InstanceInvokeExpr))
						return;

					InstanceInvokeExpr instanceExpr = (InstanceInvokeExpr) expr;

					SootMethod targetMethod = instanceExpr.getMethod();
					SootClass targetClass = targetMethod.getDeclaringClass();
					if (!targetClass.getType().equals(Types.HTTPS_URL_CONNECTION)) // TODO what if this is HTTP_URL_CONNECTION?
						return;

					if (!targetMethod.getName().equals("setHostnameVerifier"))
						return;

					// TODO check arg count?
					Value value = instanceExpr.getArg(0);
					if (!(value instanceof Local))
						return; // TODO is this always the case?

					PointsToSet set = Scene.v().getPointsToAnalysis().reachingObjects((Local) value);

					for (Type type : set.possibleTypes()) {
						if (!(type instanceof RefType))
							continue; // TODO is this always (not) the case?

						// TODO again, rather convoluted and needs reworking (e.g. what if there is a VULNERABLE _and_ a SAFE HV?)
						RefType ref = (RefType) type;
						if (ref.getSootClass().hasTag(HostnameVerifierTag.NAME)) {
							HostnameVerifierTag tag = (HostnameVerifierTag) ref.getSootClass().getTag(HostnameVerifierTag.NAME);
							vulnerabilities.add(new Vulnerability(method, VulnerabilityType.HTTPS_CONNECTION_USES_TRUST_MANAGER, tag.getState()));
						}
					}
				}
			});
		}
	}
}
