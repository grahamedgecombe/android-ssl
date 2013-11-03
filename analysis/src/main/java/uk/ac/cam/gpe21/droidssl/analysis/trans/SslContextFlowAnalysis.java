package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeStmt;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class SslContextFlowAnalysis extends ForwardFlowAnalysis<Unit, Set<Local>> {
	public SslContextFlowAnalysis(UnitGraph graph) {
		super(graph);
		doAnalysis();
	}

	@Override
	protected void flowThrough(final Set<Local> in, Unit node, final Set<Local> out) {
		node.apply(new AbstractStmtSwitch() {
			@Override
			public void caseInvokeStmt(InvokeStmt stmt) {
				out.addAll(in);

				SootMethod targetMethod = stmt.getInvokeExpr().getMethod();
				if (!targetMethod.getDeclaringClass().getType().equals(Types.SSL_CONTEXT))
					return;

				if (!targetMethod.getName().equals("init"))
					return;

				List<ValueBox> list = stmt.getInvokeExpr().getUseBoxes();
				if (list.size() < 1)
					return; /* TODO could this ever happen? */

				Value value = list.get(0).getValue();
				if (!(value instanceof Local))
					return; /* TODO could this ever happen? */

				Local local = (Local) value;
				out.add(local);
			}

			@Override
			public void caseAssignStmt(AssignStmt stmt) {
				out.addAll(in);

				Value left = stmt.getLeftOp();
				Value right = stmt.getRightOp();

				if (left instanceof Local) {
					Local left0 = (Local) left;
					if (out.contains(left0))
						out.remove(left0);

					if (right instanceof Local) {
						Local right0 = (Local) right;
						if (out.contains(right0))
							out.add(left0);
					}
				}
			}

			@Override
			public void defaultCase(Object obj) {
				out.addAll(in);
			}
		});
	}

	@Override
	protected Set<Local> newInitialFlow() {
		return new HashSet<>(); // TODO use FlowSet
	}

	@Override
	protected Set<Local> entryInitialFlow() {
		return new HashSet<>();
	}

	@Override
	protected void merge(Set<Local> in1, Set<Local> in2, Set<Local> out) {
		out.addAll(in1);
		out.addAll(in2);
	}

	@Override
	protected void copy(Set<Local> source, Set<Local> dest) {
		dest.addAll(source);
	}
}
