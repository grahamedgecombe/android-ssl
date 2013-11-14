package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityType;
import uk.ac.cam.gpe21.droidssl.analysis.tag.HostnameVerifierTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.PointsToUtils;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.List;

public final class DefaultHostnameVerifierAnalyser extends IntraProceduralAnalyser {
	public DefaultHostnameVerifierAnalyser(List<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	protected void analyse(SootClass clazz, final SootMethod method, Body body) {
		for (Unit unit : body.getUnits()) {
			unit.apply(new AbstractStmtSwitch() {
				@Override
				public void caseInvokeStmt(InvokeStmt stmt) {
					InvokeExpr expr = stmt.getInvokeExpr();
					SootMethod targetMethod = expr.getMethod();

					if (!Signatures.methodSignatureMatches(targetMethod, Types.HTTPS_URL_CONNECTION, VoidType.v(), "setDefaultHostnameVerifier", Types.HOSTNAME_VERIFIER))
						return;

					Value value = expr.getArg(0);
					if (!(value instanceof Local))
						return; // TODO e.g. could be a field ref? does soot support points-to in this case?

					VulnerabilityState state = VulnerabilityState.UNKNOWN;

					PointsToSet set = Scene.v().getPointsToAnalysis().reachingObjects((Local) value);
					if (!set.isEmpty()) {
						if (PointsToUtils.anyTypeVulnerable(set, HostnameVerifierTag.NAME)) {
							state = VulnerabilityState.VULNERABLE;
						} else if (PointsToUtils.allTypesSafe(set, HostnameVerifierTag.NAME)) {
							state = VulnerabilityState.SAFE;
						}
					}

					vulnerabilities.add(new Vulnerability(method, VulnerabilityType.HTTPS_CONNECTION_DEFAULT_HOSTNAME_VERIFIER, state));
				}
			});
		}
	}
}
