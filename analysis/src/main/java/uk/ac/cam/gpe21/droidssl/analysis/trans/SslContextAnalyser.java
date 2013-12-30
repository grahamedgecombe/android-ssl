package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityType;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.Set;

public final class SslContextAnalyser extends IntraProceduralAnalyser {
	public SslContextAnalyser(Set<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	protected void analyse(SootClass clazz, final SootMethod method, Body body) {
		UnitGraph graph = new BriefUnitGraph(body);
		final TrustManagerFlowAnalysis analysis = new TrustManagerFlowAnalysis(graph);

		for (Unit unit : graph) {
			unit.apply(new AbstractStmtSwitch() {
				@Override
				public void caseAssignStmt(AssignStmt stmt) {
					// TODO complete
				}

				@Override
				public void caseInvokeStmt(InvokeStmt stmt) {
					InvokeExpr expr = stmt.getInvokeExpr();
					if (!(expr instanceof InstanceInvokeExpr))
						return;

					InstanceInvokeExpr instanceExpr = (InstanceInvokeExpr) expr;

					SootMethod targetMethod = stmt.getInvokeExpr().getMethod();

					RefType clazz = targetMethod.getDeclaringClass().getType();
					String targetName = targetMethod.getName();

					// TODO deal with the fact it could also be SSL_SOCKET_FACTORY
					if (clazz.equals(Types.SOCKET_FACTORY) && targetName.equals("createSocket")) {
						if (analysis.getFlowBefore(stmt).contains(instanceExpr.getBase())) {
							vulnerabilities.add(new Vulnerability(method, VulnerabilityType.SOCKET_USES_PERMISSIVE_TRUST_MANAGER, VulnerabilityState.VULNERABLE));
						} // TODO: else add SAFE? or UNKNOWN? or nothing at all?
					}
				}
			});
		}
	}
}
