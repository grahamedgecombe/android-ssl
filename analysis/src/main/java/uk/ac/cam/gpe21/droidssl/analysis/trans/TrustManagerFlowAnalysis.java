package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.ForwardFlowAnalysis;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;
import uk.ac.cam.gpe21.droidssl.analysis.tag.TrustManagerTag;
import uk.ac.cam.gpe21.droidssl.analysis.util.Signatures;
import uk.ac.cam.gpe21.droidssl.analysis.util.Types;

public final class TrustManagerFlowAnalysis extends ForwardFlowAnalysis<Unit, FlowSet> {
	public TrustManagerFlowAnalysis(UnitGraph graph) {
		super(graph);
		doAnalysis();
	}

	@Override
	protected void flowThrough(final FlowSet in, Unit node, final FlowSet out) {
		node.apply(new AbstractStmtSwitch() {
			@Override
			public void caseInvokeStmt(InvokeStmt stmt) {
				in.copy(out);

				// TODO: consider super & subtypes (e.g. important for SSLSocketFactory)
				// TODO: also use methodSignatureMatches?

				InvokeExpr expr = stmt.getInvokeExpr();
				if (!(expr instanceof InstanceInvokeExpr))
					return;

				InstanceInvokeExpr instanceExpr = (InstanceInvokeExpr) expr;

				SootMethod targetMethod = stmt.getInvokeExpr().getMethod();

				RefType clazz = targetMethod.getDeclaringClass().getType();
				String method = targetMethod.getName();

				// TODO check the entire method signature
				if (Signatures.methodSignatureMatches(targetMethod, Types.SSL_CONTEXT, VoidType.v(), "init", Types.KEY_MANAGER_ARRAY, Types.TRUST_MANAGER_ARRAY, Types.SECURE_RANDOM)) {
					Value context = instanceExpr.getBase();
					Value trustManagerArray = instanceExpr.getArg(1);

					if (out.contains(trustManagerArray)) {
						out.add(context);
					}
				}
			}

			@Override
			public void caseAssignStmt(AssignStmt stmt) {
				in.copy(out);

				final Value[] leftBox = new Value[1];
				Value left = stmt.getLeftOp();
				leftBox[0] = left;
				left.apply(new AbstractJimpleValueSwitch() {
					@Override
					public void caseLocal(Local left) {
						out.remove(left);
					}

					@Override
					public void caseArrayRef(ArrayRef left) {
						leftBox[0] = left.getBase();
					}
				});

				Value right = stmt.getRightOp();
				right.apply(new AbstractJimpleValueSwitch() {
					@Override
					public void caseNewExpr(NewExpr right) {
						if (right.getBaseType().getSootClass().hasTag(TrustManagerTag.NAME)) {
							// TODO: this is rather convoluted and needs a way to deal with SAFE/UNKNOWN too
							TrustManagerTag tag = (TrustManagerTag) right.getBaseType().getSootClass().getTag(TrustManagerTag.NAME);
							if (tag.getState() == VulnerabilityState.VULNERABLE) {
								out.add(leftBox[0]);
							}
						}
					}

					@Override
					public void caseLocal(Local right) {
						if (out.contains(right)) {
							out.add(leftBox[0]);
						}
					}

					@Override
					public void caseVirtualInvokeExpr(VirtualInvokeExpr right) {
						SootMethod targetMethod = right.getMethod();

						RefType clazz = targetMethod.getDeclaringClass().getType();
						String method = targetMethod.getName();

						// TODO check the entire method signature
						if (clazz.equals(Types.SSL_CONTEXT) && method.equals("getSocketFactory")) {
							if (out.contains(right.getBase())) {
								out.add(leftBox[0]);
							}
						}
					}
				});
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
