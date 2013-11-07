package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeStmt;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.ForwardFlowAnalysis;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

import java.util.List;

public final class SslContextFlowAnalysis extends ForwardFlowAnalysis<Unit, FlowSet> {
	public SslContextFlowAnalysis(UnitGraph graph) {
		super(graph);
		doAnalysis();
	}

	@Override
	protected void flowThrough(final FlowSet in, Unit node, final FlowSet out) {
		node.apply(new AbstractStmtSwitch() {
			@Override
			public void caseInvokeStmt(InvokeStmt stmt) {
				in.copy(out);

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
				in.copy(out);

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
				in.copy(out);
			}
		});
	}

	@Override
	protected FlowSet newInitialFlow() {
		return new ArraySparseSet();
	}

	@Override
	protected FlowSet entryInitialFlow() {
		return new ArraySparseSet();
	}

	@Override
	protected void merge(FlowSet in1, FlowSet in2, FlowSet out) {
		in1.union(in2, out);
	}

	@Override
	protected void copy(FlowSet source, FlowSet dest) {
		source.copy(dest);
	}
}
