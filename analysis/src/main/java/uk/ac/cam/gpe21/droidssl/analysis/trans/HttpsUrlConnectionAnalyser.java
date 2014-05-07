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

import java.util.Set;

public final class HttpsUrlConnectionAnalyser extends IntraProceduralAnalyser {
	public HttpsUrlConnectionAnalyser(Set<Vulnerability> vulnerabilities) {
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

					// TODO what if it is casted to HTTP_URL_CONNECTION?
					if (!Signatures.methodSignatureMatches(targetMethod, Types.HTTPS_URL_CONNECTION, VoidType.v(), "setHostnameVerifier", Types.HOSTNAME_VERIFIER))
						return;

					Value value = expr.getArg(0);
					if (!(value instanceof Local))
						return;

					VulnerabilityState state = VulnerabilityState.UNKNOWN;

					PointsToSet set = Scene.v().getPointsToAnalysis().reachingObjects((Local) value);
					if (!set.isEmpty()) {
						if (PointsToUtils.anyTypeVulnerable(set, HostnameVerifierTag.NAME)) {
							state = VulnerabilityState.VULNERABLE;
						} else if (PointsToUtils.allTypesSafe(set, HostnameVerifierTag.NAME)) {
							state = VulnerabilityState.SAFE;
						}
					}

					vulnerabilities.add(new Vulnerability(method, VulnerabilityType.HTTPS_CONNECTION_USES_HOSTNAME_VERIFIER, state));
				}
			});
		}
	}
}
