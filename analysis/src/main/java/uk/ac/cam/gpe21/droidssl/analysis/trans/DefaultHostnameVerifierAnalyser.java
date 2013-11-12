package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityType;
import uk.ac.cam.gpe21.droidssl.analysis.tag.VulnerabilityTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.List;

public final class DefaultHostnameVerifierAnalyser extends Analyser {
	public DefaultHostnameVerifierAnalyser(List<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	protected void analyse(SootClass clazz, SootMethod method, Body body) {
		for (Unit unit : body.getUnits()) {
			if (unit instanceof InvokeStmt) {
				InvokeStmt stmt = (InvokeStmt) unit;
				SootMethod targetMethod = stmt.getInvokeExpr().getMethod();

				if (!targetMethod.getDeclaringClass().getType().equals(Types.HTTPS_URL_CONNECTION))
					continue;

				if (!targetMethod.getName().equals("setDefaultHostnameVerifier"))
					continue;

				if (!Signatures.methodSignatureMatches(targetMethod, VoidType.v(), Types.HOSTNAME_VERIFIER))
					continue;

				if (!targetMethod.isStatic())
					continue;

				InvokeExpr expr = stmt.getInvokeExpr(); // TODO sanity checking?
				Value value = expr.getArg(0);
				if (!(value instanceof Local))
					continue; // TODO e.g. could be a field ref? does soot support points-to in this case?

				Local local = (Local) value;

				PointsToSet set = Scene.v().getPointsToAnalysis().reachingObjects(local);
				for (Type type : set.possibleTypes()) {
					if (!(type instanceof RefType))
						continue;

					RefType ref = (RefType) type;
					if (ref.getSootClass().hasTag(VulnerabilityTag.NAME)) {
						vulnerabilities.add(new Vulnerability(body.getMethod(), VulnerabilityType.DEFAULT_HTTPS_HOSTNAME_VERIFIER));
					}
				}
			}
		}
	}
}
