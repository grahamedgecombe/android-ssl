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
import soot.jimple.AbstractJimpleValueSwitch;
import soot.jimple.NewExpr;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityType;
import uk.ac.cam.gpe21.droidssl.analysis.tag.TrustManagerTag;

import java.util.Set;

public final class InitTrustManagerAnalyser extends IntraProceduralAnalyser {
	public InitTrustManagerAnalyser(Set<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	protected void analyse(SootClass clazz, final SootMethod method, Body body) {
		for (Unit unit : body.getUnits()) {
			for (ValueBox valueBox : unit.getUseBoxes()) {
				valueBox.getValue().apply(new AbstractJimpleValueSwitch() {
					@Override
					public void caseNewExpr(NewExpr value) {
						SootClass type = value.getBaseType().getSootClass();
						if (type.hasTag(TrustManagerTag.NAME)) {
							TrustManagerTag tag = (TrustManagerTag) type.getTag(TrustManagerTag.NAME);
							vulnerabilities.add(new Vulnerability(method, VulnerabilityType.INIT_TRUST_MANAGER, tag.getState()));
						}
					}
				});
			}
		}
	}
}
