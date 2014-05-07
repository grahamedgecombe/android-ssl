/*
 * Copyright 2013-2014 Graham Edgecombe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

				/* if SSLContext.init() is called with a vulnerable TrustManager, mark the SSLContext as vulnerable */
				InvokeExpr expr = stmt.getInvokeExpr();
				if (!(expr instanceof InstanceInvokeExpr))
					return;

				InstanceInvokeExpr instanceExpr = (InstanceInvokeExpr) expr;
				SootMethod targetMethod = stmt.getInvokeExpr().getMethod();

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

				/* remove the vulnerability property from the left side of the assignment */
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

				/* check if we need to add the vulnerability property to the left side of the assignment,
				 * based on the kind of expression on the right side */
				Value right = stmt.getRightOp();
				right.apply(new AbstractJimpleValueSwitch() {
					@Override
					public void caseNewExpr(NewExpr right) {
						/* if the right side instantiates a vulnerable TrustManager, make the left side vulnerable */
						if (right.getBaseType().getSootClass().hasTag(TrustManagerTag.NAME)) {
							TrustManagerTag tag = (TrustManagerTag) right.getBaseType().getSootClass().getTag(TrustManagerTag.NAME);
							if (tag.getState() == VulnerabilityState.VULNERABLE) {
								out.add(leftBox[0]);
							}
						}
					}

					@Override
					public void caseLocal(Local right) {
						/* if the right side is vulnerable, make the left side vulnerable */
						if (out.contains(right)) {
							out.add(leftBox[0]);
						}
					}

					@Override
					public void caseVirtualInvokeExpr(VirtualInvokeExpr right) {
						/* if a vulnerable SSLContext (right) is used to make an SSLSocketFactory,
						 * mark the SSLSocketFactory (leftBox[0]) as vulnerable
						 */
						SootMethod targetMethod = right.getMethod();
						if (Signatures.methodSignatureMatches(targetMethod, Types.SSL_CONTEXT, Types.SSL_SOCKET_FACTORY, "getSocketFactory")) {
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

				/* by default: unmark any local registers which are overwritten by the instruction */
				Stmt stmt = (Stmt) obj;
				for (ValueBox box : stmt.getDefBoxes()) {
					out.remove(box.getValue());
				}
			}
		});
	}

	@Override
	protected FlowSet entryInitialFlow() {
		/* the set of vulnerable locals is empty at the entry point */
		return new ArraySparseSet();
	}

	@Override
	protected void merge(FlowSet in1, FlowSet in2, FlowSet out) {
		/* combine sets of registers by union - this means only a single
		 * path through the code needs to be considered vulnerable for the
		 * whole method to be vulnerable */
		in1.union(in2, out);
	}

	/* these aren't really related the data flow analysis per se - they just
	 * depend on the FlowSet implementation chosen
	 */
	@Override
	protected FlowSet newInitialFlow() {
		return new ArraySparseSet();
	}

	@Override
	protected void copy(FlowSet source, FlowSet dest) {
		source.copy(dest);
	}
}
